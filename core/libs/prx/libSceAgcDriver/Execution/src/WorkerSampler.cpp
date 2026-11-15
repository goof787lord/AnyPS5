#include "prx/libSceAgcDriver/Execution/include/WorkerSampler.hpp"
#include "prx/libSceAgcDriver/Execution/include/Mutex.hpp"
#include "prx/libc/include/HostThread.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include "prx/libSceAgcDriver/Execution/include/StackWalk.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <stop_token>
#include <system_error>
#include <thread>
#include <vector>
#elif defined(__linux__)
#include "prx/libSceAgcDriver/Execution/include/StackWalk.hpp"
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>
#endif

namespace AgcDriver {

#ifdef _WIN32
bool ReadableStackRegion(std::uint64_t address, std::uint64_t& low, std::uint64_t& high) {
    constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &memory, sizeof(memory)) == 0 || memory.State != MEM_COMMIT) return false;
    if ((memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 || (memory.Protect & readable) == 0) return false;
    low = reinterpret_cast<std::uint64_t>(memory.BaseAddress);
    high = low + memory.RegionSize;
    return true;
}

namespace {

std::jthread processSamplerThread;
std::jthread workerSamplerThread;
std::jthread committerSamplerThread;

std::optional<std::string> ConfiguredPath(const wchar_t* value) {
    if (value == nullptr) return std::nullopt;
    const auto text = std::filesystem::path(value).u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

std::filesystem::path NativePath(const std::string& path) {
    return std::filesystem::path(reinterpret_cast<const char8_t*>(path.c_str()));
}

std::FILE* OpenForWriting(const std::string& path) {
    return _wfopen(NativePath(path).c_str(), L"w");
}

// Debug aid: APS5_SAMPLE_WORKER=<file> samples the calling thread every millisecond and, every 20 s,
// writes "module+offset self inclusive" lines to <file> for offline symbolization with nm.
struct Sampler {
    static constexpr int ProcessDepth = 12;
    static constexpr int WorkerDepth = 64;

    HANDLE target = nullptr;
    std::string path;
    int depth = ProcessDepth;
    bool keepStacks = false;
    std::uint64_t stackLow = 0;
    std::uint64_t stackHigh = 0;
    std::vector<DwarfFrames> modules;
    std::uint64_t pendingModule = 0;
    AgcDriver::Mutex mutex;
    std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> counts;
    CollapsedStacks stacks;
    std::uint64_t samples = 0;
    std::int64_t suspendedTicks = 0;
    std::int64_t longestSuspendedTicks = 0;

    ~Sampler() noexcept(false) {
        if (target != nullptr && !CloseHandle(target)) throw std::system_error(GetLastError(), std::system_category(), "Closing sampler thread handle");
    }

    bool readStack(std::uint64_t address, std::uint64_t& value) const {
        if (stackHigh < stackLow + sizeof(value) || address < stackLow || address > stackHigh - sizeof(value)) return false;
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
        return true;
    }

    const DwarfFrames* moduleOf(std::uint64_t pc) const {
        const auto found = std::upper_bound(modules.begin(), modules.end(), pc, [](std::uint64_t value, const DwarfFrames& module) { return value < module.Base(); });
        return found != modules.begin() && std::prev(found)->Contains(pc) ? &*std::prev(found) : nullptr;
    }

    bool hasUnwindData(std::uint64_t pc) const {
        DWORD64 imageBase = 0;
        const auto* module = moduleOf(pc - 1);
        return RtlLookupFunctionEntry(pc, &imageBase, nullptr) != nullptr || (module != nullptr && module->Covers(pc - 1));
    }

    DwarfFrames::Step stepDwarf(CONTEXT& context, bool leaf) {
        const auto* module = moduleOf(context.Rip - (leaf ? 0 : 1));
        if (module == nullptr) {
            MEMORY_BASIC_INFORMATION memory{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(context.Rip), &memory, sizeof(memory)) != 0 && memory.Type == MEM_IMAGE) pendingModule = reinterpret_cast<std::uint64_t>(memory.AllocationBase);
            return DwarfFrames::Step::Failed;
        }
        DwarfFrames::Registers registers{context.Rax, context.Rdx, context.Rcx, context.Rbx, context.Rsi, context.Rdi, context.Rbp, context.Rsp, context.R8, context.R9, context.R10, context.R11, context.R12, context.R13, context.R14, context.R15, context.Rip};
        const auto step = module->Unwind(registers, leaf, [&](std::uint64_t address, std::uint64_t& value) { return readStack(address, value); });
        if (step != DwarfFrames::Step::Stepped) return step;
        DWORD64* columns[] = {&context.Rax, &context.Rdx, &context.Rcx, &context.Rbx, &context.Rsi, &context.Rdi, &context.Rbp, &context.Rsp, &context.R8, &context.R9, &context.R10, &context.R11, &context.R12, &context.R13, &context.R14, &context.R15, &context.Rip};
        for (std::size_t column = 0; column < registers.size(); ++column) *columns[column] = registers[column];
        return step;
    }

    int walk(CONTEXT& context, std::array<std::uint64_t, WorkerDepth>& frames) {
        if (context.Rsp < stackLow || context.Rsp >= stackHigh) {
            stackLow = 0;
            stackHigh = 0;
            ReadableStackRegion(context.Rsp, stackLow, stackHigh);
        }
        const bool dwarf = stackHigh != 0 && context.Rsp >= stackLow && context.Rsp < stackHigh;
        int count = 0;
        while (count < depth && context.Rip != 0) {
            frames[count++] = context.Rip;
            DWORD64 imageBase = 0;
            if (auto* entry = RtlLookupFunctionEntry(context.Rip, &imageBase, nullptr)) {
                PVOID handler = nullptr;
                DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip, entry, &context, &handler, &establisher, nullptr);
                continue;
            }
            if (!dwarf) break;
            const auto step = stepDwarf(context, count == 1);
            if (step == DwarfFrames::Step::Stepped) continue;
            std::uint64_t returnAddress = 0;
            if (step == DwarfFrames::Step::Failed || count != 1 || !readStack(context.Rsp, returnAddress) || !hasUnwindData(returnAddress)) break;
            context.Rip = returnAddress;
            context.Rsp += sizeof(returnAddress);
        }
        return count;
    }

    void indexModule() {
        const auto base = std::exchange(pendingModule, 0);
        if (moduleOf(base) != nullptr) return;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        const DwarfFrames::Byte* frames = nullptr;
        const DwarfFrames::Byte* framesEnd = nullptr;
        for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
            if (std::memcmp(sections[index].Name, ".ehfram", 8) != 0) continue;
            frames = reinterpret_cast<const DwarfFrames::Byte*>(base + sections[index].VirtualAddress);
            framesEnd = frames + sections[index].Misc.VirtualSize;
        }
        const auto at = std::upper_bound(modules.begin(), modules.end(), base, [](std::uint64_t value, const DwarfFrames& module) { return value < module.Base(); });
        modules.emplace(at, base, base + nt->OptionalHeader.SizeOfImage, frames, framesEnd);
    }

    void sample() {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        std::array<std::uint64_t, WorkerDepth> frames;
        int count = 0;
        LARGE_INTEGER suspended{};
        LARGE_INTEGER resumed{};
        QueryPerformanceCounter(&suspended);
        if (SuspendThread(target) == static_cast<DWORD>(-1)) return;
        if (GetThreadContext(target, &context) != 0) count = walk(context, frames);
        ResumeThread(target);
        QueryPerformanceCounter(&resumed);
        if (pendingModule != 0) indexModule();
        std::lock_guard lock(mutex);
        ++samples;
        suspendedTicks += resumed.QuadPart - suspended.QuadPart;
        longestSuspendedTicks = std::max(longestSuspendedTicks, resumed.QuadPart - suspended.QuadPart);
        for (int i = 0; i < count; ++i) {
            auto& entry = counts[frames[i]];
            if (i == 0) ++entry.first;
            ++entry.second;
        }
        if (keepStacks && count != 0) stacks.Add({frames.data(), static_cast<std::size_t>(count)}, context.Rip != 0);
    }

    static std::string frameName(std::uint64_t address, std::map<std::uint64_t, std::string>& loaded) {
        HMODULE module = nullptr;
        char name[MAX_PATH] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(address), &module)) GetModuleFileNameA(module, name, sizeof(name));
        const char* base = std::strrchr(name, '\\');
        if (module != nullptr) loaded.emplace(reinterpret_cast<std::uint64_t>(module), base ? base + 1 : name);
        char frame[MAX_PATH + 32];
        std::snprintf(frame, sizeof(frame), "%s+0x%llx", base ? base + 1 : name, static_cast<unsigned long long>(address - reinterpret_cast<std::uint64_t>(module)));
        return frame;
    }

    static void writeModules(std::FILE* file, const std::map<std::uint64_t, std::string>& loaded) {
        for (const auto& [base, name] : loaded) {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            std::fprintf(file, "# module %s 0x%lx 0x%lx\n", name.c_str(), static_cast<unsigned long>(nt->OptionalHeader.SizeOfImage), static_cast<unsigned long>(nt->FileHeader.TimeDateStamp));
        }
    }

    void write() {
        std::lock_guard lock(mutex);
        std::FILE* file = OpenForWriting(path);
        if (file == nullptr) return;
        std::fprintf(file, "# %llu samples\n", static_cast<unsigned long long>(samples));
        std::map<std::uint64_t, std::string> loaded;
        for (const auto& [address, count] : counts) {
            HMODULE module = nullptr;
            char name[MAX_PATH] = "?";
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(address), &module)) GetModuleFileNameA(module, name, sizeof(name));
            const char* base = std::strrchr(name, '\\');
            if (module != nullptr) loaded.emplace(reinterpret_cast<std::uint64_t>(module), base ? base + 1 : name);
            std::fprintf(file, "%s 0x%llx %llu %llu\n", base ? base + 1 : name, static_cast<unsigned long long>(address - reinterpret_cast<std::uint64_t>(module)), static_cast<unsigned long long>(count.first), static_cast<unsigned long long>(count.second));
        }
        writeModules(file, loaded);
        std::fclose(file);
        if (keepStacks) writeStacks();
    }

    void writeStacks() {
        const auto dot = path.rfind('.');
        const auto slash = path.find_last_of("\\/");
        const auto stem = dot != std::string::npos && (slash == std::string::npos || dot > slash) ? path.substr(0, dot) : path;
        const auto collapsed = stem + ".collapsed.txt";
        const auto temporary = collapsed + ".tmp";
        std::map<std::uint64_t, std::string> names;
        std::map<std::uint64_t, std::string> loaded;
        for (const auto& [address, count] : counts) names.emplace(address, frameName(address, loaded));
        std::FILE* file = OpenForWriting(temporary);
        if (file == nullptr) return;
        LARGE_INTEGER frequency{};
        QueryPerformanceFrequency(&frequency);
        const double tickUs = 1e6 / static_cast<double>(frequency.QuadPart);
        std::fprintf(file, "# samples=%llu depth=%d truncated=%llu suspended_us_mean=%.1f suspended_us_max=%.1f\n", static_cast<unsigned long long>(samples), depth, static_cast<unsigned long long>(stacks.Truncated()),
            samples != 0 ? static_cast<double>(suspendedTicks) * tickUs / static_cast<double>(samples) : 0.0, static_cast<double>(longestSuspendedTicks) * tickUs);
        writeModules(file, loaded);
        const auto text = stacks.Format([&](std::uint64_t address) { return names.at(address); });
        const bool written = std::fwrite(text.data(), 1, text.size(), file) == text.size();
        if (std::fclose(file) != 0 || !written) return;
        MoveFileExW(NativePath(temporary).c_str(), NativePath(collapsed).c_str(), MOVEFILE_REPLACE_EXISTING);
    }
};

// Debug aid: APS5_SAMPLE_THREADS=<file> samples every thread in the process every 2 ms and, every
// 20 s, writes each busy thread's hottest frames ("module+offset self inclusive") to <file>.
struct ProcessSampler {
    std::string path;
    DWORD self = 0;
    std::map<DWORD, Sampler> threads;
    std::uint64_t rounds = 0;

    std::chrono::steady_clock::time_point enumerated{};

    // The system-wide thread snapshot is slow (tens of ms); the thread list is refreshed every 5 s and
    // the rounds in between only sample the known threads.
    void enumerate() {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        const DWORD process = GetCurrentProcessId();
        for (BOOL more = Thread32First(snapshot, &entry); more; more = Thread32Next(snapshot, &entry)) {
            if (entry.th32OwnerProcessID != process || entry.th32ThreadID == self) continue;
            auto& thread = threads[entry.th32ThreadID];
            if (thread.target == nullptr) thread.target = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
        }
        CloseHandle(snapshot);
        enumerated = std::chrono::steady_clock::now();
    }

    void sample() {
        if (threads.empty() || std::chrono::steady_clock::now() - enumerated > std::chrono::seconds(5)) enumerate();
        for (auto& [id, thread] : threads) {
            if (thread.target != nullptr) thread.sample();
        }
        ++rounds;
    }

    void write() {
        std::FILE* file = OpenForWriting(path);
        if (file == nullptr) return;
        std::fprintf(file, "# %llu rounds\n", static_cast<unsigned long long>(rounds));
        std::map<std::uint64_t, std::string> loaded;
        for (auto& [id, thread] : threads) {
            std::lock_guard lock(thread.mutex);
            std::vector<std::pair<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>>> hot(thread.counts.begin(), thread.counts.end());
            std::sort(hot.begin(), hot.end(), [](const auto& a, const auto& b) { return a.second.second > b.second.second; });
            std::uint64_t leaves = 0;
            for (const auto& [address, count] : hot) leaves += count.first;
            if (leaves == 0) continue;
            std::fprintf(file, "thread %lu samples %llu\n", static_cast<unsigned long>(id), static_cast<unsigned long long>(thread.samples));
            for (std::size_t i = 0; i < hot.size() && i < 40; ++i) {
                const auto address = hot[i].first;
                HMODULE module = nullptr;
                char name[MAX_PATH] = "?";
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(address), &module)) GetModuleFileNameA(module, name, sizeof(name));
                const char* base = std::strrchr(name, '\\');
                if (module != nullptr) loaded.emplace(reinterpret_cast<std::uint64_t>(module), base ? base + 1 : name);
                std::fprintf(file, "  %s 0x%llx %llu %llu\n", base ? base + 1 : name, static_cast<unsigned long long>(address - reinterpret_cast<std::uint64_t>(module)), static_cast<unsigned long long>(hot[i].second.first), static_cast<unsigned long long>(hot[i].second.second));
            }
        }
        Sampler::writeModules(file, loaded);
        std::fclose(file);
    }
};

void StartProcessSampler() {
    const auto path = ConfiguredPath(_wgetenv(L"APS5_SAMPLE_THREADS"));
    if (!path) return;
    processSamplerThread = Libc::StartHostJThread([path = *path](std::stop_token token) {
        auto sampler = std::make_unique<ProcessSampler>();
        sampler->path = path;
        sampler->self = GetCurrentThreadId();
        auto flushed = std::chrono::steady_clock::now();
        while (!token.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            sampler->sample();
            if (std::chrono::steady_clock::now() - flushed > std::chrono::seconds(20)) {
                sampler->write();
                flushed = std::chrono::steady_clock::now();
            }
        }
        sampler->write();
    });
}

void StartCallingThreadSampler(const std::optional<std::string>& path, std::jthread& slot) {
    if (!path) return;
    auto sampler = std::make_unique<Sampler>();
    sampler->path = *path;
    sampler->depth = Sampler::WorkerDepth;
    sampler->keepStacks = true;
    const auto* block = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    MEMORY_BASIC_INFORMATION stack{};
    if (VirtualQuery(block->StackLimit, &stack, sizeof(stack)) != 0) {
        sampler->stackLow = reinterpret_cast<std::uint64_t>(stack.AllocationBase);
        sampler->stackHigh = reinterpret_cast<std::uint64_t>(block->StackBase);
    }
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &sampler->target, THREAD_ALL_ACCESS, FALSE, 0)) throw std::system_error(GetLastError(), std::system_category(), "Duplicating sampler thread handle");
    slot = Libc::StartHostJThread([sampler = std::move(sampler)](std::stop_token token) {
        auto flushed = std::chrono::steady_clock::now();
        while (!token.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            sampler->sample();
            if (std::chrono::steady_clock::now() - flushed > std::chrono::seconds(20)) {
                sampler->write();
                flushed = std::chrono::steady_clock::now();
            }
        }
        sampler->write();
    });
}

}

void StartWorkerSampler(std::uint32_t queue) {
    if (queue == 0) StartProcessSampler();
    static const auto sampledQueue = [] {
        const char* value = std::getenv("APS5_SAMPLE_WORKER_QUEUE");
        return value != nullptr ? static_cast<std::uint32_t>(std::strtoul(value, nullptr, 0)) : 0u;
    }();
    if (queue == sampledQueue) StartCallingThreadSampler(ConfiguredPath(_wgetenv(L"APS5_SAMPLE_WORKER")), workerSamplerThread);
}

void StartCommitterSampler() {
    StartCallingThreadSampler(ConfiguredPath(_wgetenv(L"APS5_SAMPLE_COMMITTER")), committerSamplerThread);
}

void StopWorkerSampler() {
    processSamplerThread.request_stop();
    workerSamplerThread.request_stop();
    committerSamplerThread.request_stop();
    if (processSamplerThread.joinable()) processSamplerThread.join();
    if (workerSamplerThread.joinable()) workerSamplerThread.join();
    if (committerSamplerThread.joinable()) committerSamplerThread.join();
}
#elif defined(__linux__)
bool ReadableStackRegion(std::uint64_t, std::uint64_t&, std::uint64_t&) {
    return false;
}

namespace {

constexpr int SampleDepth = 64;
constexpr std::size_t RingSlots = 4096;
constexpr int SampleSignal = SIGPROF;

std::jthread workerSamplerThread;
std::jthread committerSamplerThread;

struct RawSample {
    std::array<std::uint64_t, SampleDepth> frames;
    std::uint32_t count;
    std::uint32_t truncated;
    std::uint64_t handlerNs;
};

struct ModuleRecord {
    std::string name;
    std::uint64_t bias = 0;
    std::uint64_t low = 0;
    std::uint64_t high = 0;
    std::unique_ptr<DwarfFrames> frames;
};

using ModuleList = std::vector<const ModuleRecord*>;

const ModuleRecord* FindModule(const ModuleList& modules, std::uint64_t address) {
    const auto found = std::upper_bound(modules.begin(), modules.end(), address, [](std::uint64_t value, const ModuleRecord* module) { return value < module->low; });
    if (found == modules.begin()) return nullptr;
    const ModuleRecord* module = *std::prev(found);
    return address < module->high ? module : nullptr;
}

std::string ModuleName(const char* path) {
    std::string name = path != nullptr ? path : "";
    if (name.empty()) {
        char buffer[4096];
        const auto length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
        if (length > 0) name.assign(buffer, static_cast<std::size_t>(length));
    }
    const auto slash = name.find_last_of('/');
    return slash == std::string::npos ? name : name.substr(slash + 1);
}

bool DecodeEncoded(const DwarfFrames::Byte*& cursor, DwarfFrames::Byte encoding, std::uint64_t dataBase, std::uint64_t& value) {
    if (encoding == 0xff) return false;
    const auto field = reinterpret_cast<std::uint64_t>(cursor);
    std::int64_t raw = 0;
    switch (encoding & 0x0f) {
    case 0x00:
    case 0x04:
    case 0x0c: {
        std::uint64_t word = 0;
        std::memcpy(&word, cursor, sizeof(word));
        cursor += sizeof(word);
        raw = static_cast<std::int64_t>(word);
        break;
    }
    case 0x03: {
        std::uint32_t word = 0;
        std::memcpy(&word, cursor, sizeof(word));
        cursor += sizeof(word);
        raw = static_cast<std::int64_t>(word);
        break;
    }
    case 0x0b: {
        std::int32_t word = 0;
        std::memcpy(&word, cursor, sizeof(word));
        cursor += sizeof(word);
        raw = word;
        break;
    }
    default:
        return false;
    }
    switch (encoding & 0x70) {
    case 0x00:
        value = static_cast<std::uint64_t>(raw);
        return true;
    case 0x10:
        value = field + static_cast<std::uint64_t>(raw);
        return true;
    case 0x30:
        value = dataBase + static_cast<std::uint64_t>(raw);
        return true;
    default:
        return false;
    }
}

const DwarfFrames::Byte* EndOfFrames(const DwarfFrames::Byte* frames, std::uint64_t limit) {
    const DwarfFrames::Byte* p = frames;
    while (reinterpret_cast<std::uint64_t>(p) + sizeof(std::uint32_t) <= limit) {
        std::uint32_t length = 0;
        std::memcpy(&length, p, sizeof(length));
        p += sizeof(length);
        if (length == 0) return p;
        if (length == 0xffffffff || reinterpret_cast<std::uint64_t>(p) + length > limit) return nullptr;
        p += length;
    }
    return nullptr;
}

bool LocateFrames(const dl_phdr_info& info, std::uint64_t limit, const DwarfFrames::Byte*& frames, const DwarfFrames::Byte*& end) {
    const ElfW(Phdr)* header = nullptr;
    for (unsigned index = 0; index < info.dlpi_phnum; ++index) {
        if (info.dlpi_phdr[index].p_type == PT_GNU_EH_FRAME) header = &info.dlpi_phdr[index];
    }
    if (header == nullptr || header->p_memsz < 8) return false;
    const auto* table = reinterpret_cast<const DwarfFrames::Byte*>(info.dlpi_addr + header->p_vaddr);
    if (table[0] != 1) return false;
    const DwarfFrames::Byte* cursor = table + 4;
    std::uint64_t start = 0;
    if (!DecodeEncoded(cursor, table[1], reinterpret_cast<std::uint64_t>(table), start)) return false;
    frames = reinterpret_cast<const DwarfFrames::Byte*>(start);
    end = EndOfFrames(frames, limit);
    return end != nullptr;
}

class ModuleCatalog {
public:
    ModuleCatalog() {
        refresh();
    }

    void refresh() {
        Collection collection{this, false};
        dl_iterate_phdr(&Collect, &collection);
        if (!collection.added) return;
        auto list = std::make_unique<ModuleList>();
        for (const auto& module : owned) list->push_back(module.get());
        std::sort(list->begin(), list->end(), [](const ModuleRecord* a, const ModuleRecord* b) { return a->low < b->low; });
        const ModuleList* published = list.get();
        lists.push_back(std::move(list));
        current.store(published, std::memory_order_release);
    }

    const ModuleList* modules() const {
        return current.load(std::memory_order_acquire);
    }

private:
    struct Collection {
        ModuleCatalog* catalog;
        bool added;
    };

    static int Collect(dl_phdr_info* info, std::size_t, void* data) {
        auto& collection = *static_cast<Collection*>(data);
        std::uint64_t low = ~std::uint64_t(0);
        std::uint64_t high = 0;
        for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
            const auto& header = info->dlpi_phdr[index];
            if (header.p_type != PT_LOAD) continue;
            low = std::min<std::uint64_t>(low, header.p_vaddr);
            high = std::max<std::uint64_t>(high, header.p_vaddr + header.p_memsz);
        }
        if (low >= high) return 0;
        auto& catalog = *collection.catalog;
        const std::uint64_t start = info->dlpi_addr + low;
        for (const auto& known : catalog.owned) {
            if (known->low == start) return 0;
        }
        auto module = std::make_unique<ModuleRecord>();
        module->name = ModuleName(info->dlpi_name);
        module->bias = info->dlpi_addr;
        module->low = start;
        module->high = info->dlpi_addr + high;
        const DwarfFrames::Byte* frames = nullptr;
        const DwarfFrames::Byte* end = nullptr;
        if (LocateFrames(*info, module->high, frames, end)) module->frames = std::make_unique<DwarfFrames>(module->low, module->high, frames, end);
        catalog.owned.push_back(std::move(module));
        collection.added = true;
        return 0;
    }

    std::vector<std::unique_ptr<ModuleRecord>> owned;
    std::vector<std::unique_ptr<ModuleList>> lists;
    std::atomic<const ModuleList*> current{nullptr};
};

class ThreadSampler;

struct HandlerRegistry {
    std::array<std::atomic<ThreadSampler*>, 4> entries;
    std::atomic<int> running;
};

HandlerRegistry registry;

class ThreadSampler {
public:
    ThreadSampler(std::string path, pid_t tid, std::uint64_t stackLow, std::uint64_t stackHigh)
        : path(std::move(path)), tid(tid), stackLow(stackLow), stackHigh(stackHigh), ring(RingSlots) {}

    void run(std::stop_token token) {
        catalog = std::make_unique<ModuleCatalog>();
        const bool installed = install();
        auto flushed = std::chrono::steady_clock::now();
        while (installed && !token.stop_requested() && deliver()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            drain();
            if (refreshWanted.exchange(false, std::memory_order_relaxed)) catalog->refresh();
            if (std::chrono::steady_clock::now() - flushed > std::chrono::seconds(20)) {
                write();
                flushed = std::chrono::steady_clock::now();
            }
        }
        remove();
        drain();
        write();
    }

private:
    static void Handle(int, siginfo_t* info, void* context) {
        const int savedErrno = errno;
        registry.running.fetch_add(1);
        if (info != nullptr && info->si_code == SI_QUEUE) {
            for (auto& slot : registry.entries) {
                ThreadSampler* sampler = slot.load();
                if (sampler != nullptr && sampler == info->si_value.sival_ptr) {
                    sampler->capture(*static_cast<const ucontext_t*>(context));
                    break;
                }
            }
        }
        registry.running.fetch_sub(1);
        errno = savedErrno;
    }

    bool install() {
        static std::once_flag once;
        std::call_once(once, [] {
            struct sigaction action {};
            action.sa_sigaction = &ThreadSampler::Handle;
            action.sa_flags = SA_SIGINFO | SA_RESTART;
            sigemptyset(&action.sa_mask);
            sigaction(SampleSignal, &action, nullptr);
        });
        for (auto& slot : registry.entries) {
            ThreadSampler* expected = nullptr;
            if (slot.compare_exchange_strong(expected, this)) {
                registered = &slot;
                return true;
            }
        }
        return false;
    }

    void remove() {
        if (registered == nullptr) return;
        registered->store(nullptr);
        registered = nullptr;
        while (registry.running.load() != 0) std::this_thread::yield();
    }

    bool deliver() {
        siginfo_t info{};
        info.si_signo = SampleSignal;
        info.si_code = SI_QUEUE;
        info.si_pid = getpid();
        info.si_uid = getuid();
        info.si_value.sival_ptr = this;
        return syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SampleSignal, &info) == 0 || errno != ESRCH;
    }

    bool readStack(std::uint64_t address, std::uint64_t& value) const {
        if (stackHigh < stackLow + sizeof(value) || address < stackLow || address > stackHigh - sizeof(value)) return false;
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
        return true;
    }

    void capture(const ucontext_t& context) {
        timespec started{};
        clock_gettime(CLOCK_MONOTONIC_RAW, &started);
        const std::uint64_t slot = produced.load(std::memory_order_relaxed);
        if (slot - consumed.load(std::memory_order_acquire) >= RingSlots) {
            dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        RawSample& sample = ring[slot % RingSlots];
        const auto& gregs = context.uc_mcontext.gregs;
        DwarfFrames::Registers registers{static_cast<std::uint64_t>(gregs[REG_RAX]), static_cast<std::uint64_t>(gregs[REG_RDX]), static_cast<std::uint64_t>(gregs[REG_RCX]),
            static_cast<std::uint64_t>(gregs[REG_RBX]), static_cast<std::uint64_t>(gregs[REG_RSI]), static_cast<std::uint64_t>(gregs[REG_RDI]),
            static_cast<std::uint64_t>(gregs[REG_RBP]), static_cast<std::uint64_t>(gregs[REG_RSP]), static_cast<std::uint64_t>(gregs[REG_R8]),
            static_cast<std::uint64_t>(gregs[REG_R9]), static_cast<std::uint64_t>(gregs[REG_R10]), static_cast<std::uint64_t>(gregs[REG_R11]),
            static_cast<std::uint64_t>(gregs[REG_R12]), static_cast<std::uint64_t>(gregs[REG_R13]), static_cast<std::uint64_t>(gregs[REG_R14]),
            static_cast<std::uint64_t>(gregs[REG_R15]), static_cast<std::uint64_t>(gregs[REG_RIP])};
        const ModuleList* modules = catalog->modules();
        std::uint32_t count = 0;
        bool leaf = true;
        bool complete = false;
        while (count < SampleDepth) {
            const std::uint64_t pc = registers[16];
            if (pc == 0) {
                complete = true;
                break;
            }
            sample.frames[count++] = pc;
            const ModuleRecord* module = modules != nullptr ? FindModule(*modules, pc - (leaf ? 0 : 1)) : nullptr;
            if (module == nullptr) {
                refreshWanted.store(true, std::memory_order_relaxed);
                break;
            }
            if (module->frames == nullptr) break;
            const auto step = module->frames->Unwind(registers, leaf, [this](std::uint64_t address, std::uint64_t& value) { return readStack(address, value); });
            if (step == DwarfFrames::Step::NoRecord && leaf) {
                std::uint64_t returnAddress = 0;
                if (!readStack(registers[7], returnAddress) || modules == nullptr || FindModule(*modules, returnAddress - 1) == nullptr) break;
                registers[16] = returnAddress;
                registers[7] += sizeof(returnAddress);
                leaf = false;
                continue;
            }
            if (step != DwarfFrames::Step::Stepped) break;
            leaf = false;
        }
        sample.count = count;
        sample.truncated = complete ? 0 : 1;
        timespec finished{};
        clock_gettime(CLOCK_MONOTONIC_RAW, &finished);
        sample.handlerNs = static_cast<std::uint64_t>(finished.tv_sec - started.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(finished.tv_nsec - started.tv_nsec);
        produced.store(slot + 1, std::memory_order_release);
    }

    void drain() {
        const std::uint64_t available = produced.load(std::memory_order_acquire);
        std::uint64_t next = consumed.load(std::memory_order_relaxed);
        for (; next < available; ++next) {
            const RawSample& sample = ring[next % RingSlots];
            ++samples;
            handlerNsTotal += sample.handlerNs;
            handlerNsMax = std::max(handlerNsMax, sample.handlerNs);
            if (sample.truncated != 0) ++truncatedStacks;
            for (std::uint32_t index = 0; index < sample.count; ++index) {
                auto& entry = counts[sample.frames[index]];
                if (index == 0) ++entry.first;
                ++entry.second;
            }
            if (sample.count != 0) stacks.Add({sample.frames.data(), sample.count}, sample.truncated != 0);
        }
        consumed.store(next, std::memory_order_release);
    }

    std::string frameName(std::uint64_t address, std::map<std::uint64_t, const ModuleRecord*>& used) const {
        const ModuleList* modules = catalog->modules();
        const ModuleRecord* module = modules != nullptr ? FindModule(*modules, address) : nullptr;
        char frame[512];
        if (module == nullptr) {
            std::snprintf(frame, sizeof(frame), "?+0x%llx", static_cast<unsigned long long>(address));
            return frame;
        }
        used.emplace(module->low, module);
        std::snprintf(frame, sizeof(frame), "%s+0x%llx", module->name.c_str(), static_cast<unsigned long long>(address - module->bias));
        return frame;
    }

    static void WriteModules(std::FILE* file, const std::map<std::uint64_t, const ModuleRecord*>& used) {
        for (const auto& entry : used) {
            std::fprintf(file, "# module %s 0x%llx 0x0\n", entry.second->name.c_str(), static_cast<unsigned long long>(entry.second->high - entry.second->low));
        }
    }

    void write() {
        std::FILE* file = std::fopen(path.c_str(), "w");
        if (file == nullptr) return;
        std::fprintf(file, "# %llu samples\n", static_cast<unsigned long long>(samples));
        std::map<std::uint64_t, const ModuleRecord*> used;
        for (const auto& [address, count] : counts) {
            const auto name = frameName(address, used);
            const auto offset = name.rfind('+');
            std::fprintf(file, "%.*s %s %llu %llu\n", static_cast<int>(offset), name.c_str(), name.c_str() + offset + 1, static_cast<unsigned long long>(count.first),
                static_cast<unsigned long long>(count.second));
        }
        WriteModules(file, used);
        std::fclose(file);
        writeStacks();
    }

    void writeStacks() {
        const auto dot = path.rfind('.');
        const auto slash = path.find_last_of('/');
        const auto stem = dot != std::string::npos && (slash == std::string::npos || dot > slash) ? path.substr(0, dot) : path;
        const auto collapsed = stem + ".collapsed.txt";
        const auto temporary = collapsed + ".tmp";
        std::map<std::uint64_t, const ModuleRecord*> used;
        std::map<std::uint64_t, std::string> names;
        for (const auto& entry : counts) names.emplace(entry.first, frameName(entry.first, used));
        std::FILE* file = std::fopen(temporary.c_str(), "w");
        if (file == nullptr) return;
        const double count = static_cast<double>(samples);
        std::fprintf(file, "# samples=%llu depth=%d truncated=%llu suspended_us_mean=%.1f suspended_us_max=%.1f\n", static_cast<unsigned long long>(samples), SampleDepth,
            static_cast<unsigned long long>(truncatedStacks), samples != 0 ? static_cast<double>(handlerNsTotal) / 1000.0 / count : 0.0, static_cast<double>(handlerNsMax) / 1000.0);
        WriteModules(file, used);
        const auto text = stacks.Format([&](std::uint64_t address) { return names.at(address); });
        const bool written = std::fwrite(text.data(), 1, text.size(), file) == text.size();
        if (std::fclose(file) != 0 || !written) return;
        std::error_code error;
        std::filesystem::rename(temporary, collapsed, error);
    }

    std::string path;
    pid_t tid;
    std::uint64_t stackLow;
    std::uint64_t stackHigh;
    std::vector<RawSample> ring;
    std::unique_ptr<ModuleCatalog> catalog;
    std::atomic<std::uint64_t> produced{0};
    std::atomic<std::uint64_t> consumed{0};
    std::atomic<std::uint64_t> dropped{0};
    std::atomic<bool> refreshWanted{false};
    std::atomic<ThreadSampler*>* registered = nullptr;
    std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> counts;
    CollapsedStacks stacks;
    std::uint64_t samples = 0;
    std::uint64_t truncatedStacks = 0;
    std::uint64_t handlerNsTotal = 0;
    std::uint64_t handlerNsMax = 0;
};

std::optional<std::string> ConfiguredPath(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') return std::nullopt;
    return std::string(value);
}

void StartCallingThreadSampler(const std::optional<std::string>& path, std::jthread& slot) {
    if (!path) return;
    std::uint64_t low = 0;
    std::uint64_t high = 0;
    pthread_attr_t attributes;
    if (pthread_getattr_np(pthread_self(), &attributes) == 0) {
        void* address = nullptr;
        std::size_t size = 0;
        if (pthread_attr_getstack(&attributes, &address, &size) == 0) {
            low = reinterpret_cast<std::uint64_t>(address);
            high = low + size;
        }
        pthread_attr_destroy(&attributes);
    }
    auto sampler = std::make_unique<ThreadSampler>(*path, static_cast<pid_t>(syscall(SYS_gettid)), low, high);
    slot = Libc::StartHostJThread([sampler = std::move(sampler)](std::stop_token token) { sampler->run(token); });
}

}

void StartWorkerSampler(std::uint32_t queue) {
    static const auto sampledQueue = [] {
        const char* value = std::getenv("APS5_SAMPLE_WORKER_QUEUE");
        return value != nullptr ? static_cast<std::uint32_t>(std::strtoul(value, nullptr, 0)) : 0u;
    }();
    if (queue == sampledQueue) StartCallingThreadSampler(ConfiguredPath("APS5_SAMPLE_WORKER"), workerSamplerThread);
}

void StartCommitterSampler() {
    StartCallingThreadSampler(ConfiguredPath("APS5_SAMPLE_COMMITTER"), committerSamplerThread);
}

void StopWorkerSampler() {
    workerSamplerThread.request_stop();
    committerSamplerThread.request_stop();
    if (workerSamplerThread.joinable()) workerSamplerThread.join();
    if (committerSamplerThread.joinable()) committerSamplerThread.join();
}
#else
bool ReadableStackRegion(std::uint64_t, std::uint64_t&, std::uint64_t&) { return false; }
void StartWorkerSampler(std::uint32_t) {}
void StartCommitterSampler() {}
void StopWorkerSampler() {}
#endif

}
