#include "prx/libSceAgcDriver/Execution/include/WorkerSampler.hpp"
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

[[gnu::noinline]] std::uint64_t Spin(std::uint64_t seed) {
    std::uint64_t value = seed;
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
    while (std::chrono::steady_clock::now() < until) value = value * 6364136223846793005ull + 1442695040888963407ull;
    return value;
}

[[gnu::noinline]] std::uint64_t Middle(std::uint64_t seed) {
    return Spin(seed) + 1;
}

[[gnu::noinline]] std::uint64_t Outer(std::uint64_t seed) {
    return Middle(seed) + 1;
}

}

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    const std::string mode = argv[1];
    const bool selected = mode == "selected";
    const bool expected = selected || mode == "default";
    const auto stem = std::filesystem::temp_directory_path() / ("anyps5-sampler-" + std::to_string(getpid()));
    auto workerPath = stem;
    workerPath += "-worker.txt";
    setenv("APS5_SAMPLE_WORKER", workerPath.c_str(), 1);
    if (mode == "default") {
        unsetenv("APS5_SAMPLE_WORKER_QUEUE");
    } else {
        setenv("APS5_SAMPLE_WORKER_QUEUE", "0x50", 1);
    }
    AgcDriver::StartWorkerSampler(selected ? 0x50 : 0);
    const std::uint64_t result = Outer(1);
    AgcDriver::StopWorkerSampler();
    auto collapsed = stem;
    collapsed += "-worker.collapsed.txt";
    auto temporary = collapsed;
    temporary += ".tmp";
    const auto sampled = [&] {
        std::ifstream file(workerPath);
        std::string marker;
        std::uint64_t samples = 0;
        return (file >> marker >> samples) && marker == "#" && samples != 0;
    };
    const auto published = [&] {
        std::ifstream file(collapsed);
        std::string line;
        unsigned long long samples = 0;
        if (!std::getline(file, line) || std::sscanf(line.c_str(), "# samples=%llu", &samples) != 1 || samples == 0) return false;
        bool deep = false;
        while (std::getline(file, line)) {
            if (!line.empty() && line.front() != '#' && std::count(line.begin(), line.end(), ';') >= 2) deep = true;
        }
        return deep && !std::filesystem::exists(temporary);
    };
    const bool passed = result != 0 && sampled() == expected && published() == expected;
    std::filesystem::remove(workerPath);
    std::filesystem::remove(collapsed);
    std::filesystem::remove(temporary);
    std::printf("worker sampler %s: %s\n", mode.c_str(), passed ? "passed" : "failed");
    return passed ? 0 : 1;
}
