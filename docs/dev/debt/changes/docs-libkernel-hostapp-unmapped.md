# libkernel

## add Functional

- [`/hostapp` is not a mount](../../../core/libs/prx/libkernel/AppMetadata/src/AppMetadata.cpp) (libkernel) - only `/app0`, the `/mnt/sandbox/<titleId>_000/app0` alias, `download0` and `data` are set up, so a path under `/hostapp` resolves relative to the working directory of the executable. Dead Space (PPSA03845, 01.000.006) opens `/hostapp/Data/layout.toc` and `/hostapp/Data/initfs_Ps5` first, then reads its `streaminginstall` packages and `/hostapp/Patch/layout.toc` through the same prefix; both first opens fail with `0x80020002`, the title raises `sceKernelDebugRaiseExceptionOnReleaseMode` twice and makes no further progress. With `hostapp` linked to the title's own directory beside the executable it loads its data and renders. What `/hostapp` is on the console (its relation to `/app0`, whether it is read-only, what else it holds) is unmeasured, so no alias is added. See [discussion 20973](https://github.com/boykopovar/AnyPS5/discussions/20973).
