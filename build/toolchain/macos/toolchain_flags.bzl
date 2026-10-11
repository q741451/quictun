"""Shared flag-list helpers for the pinned clang cc_toolchains in this
directory's BUILD.bazel: the macOS counterparts of
build/toolchain/toolchain_flags.bzl, one for one."""

load(":toolchain_paths.bzl", "SDK_PATH", "TOOLCHAIN_PREFIX")

def sysroot_flags():
    """Points clang at the pinned macOS SDK (see setup_toolchain_macos.sh).

    One SDK serves every architecture, so unlike the Linux helper this takes
    none: the SDK carries both arm64 and x86_64.
    """
    return ["-isysroot", SDK_PATH]

def libcxx_compile_flags(arch):
    return [
        "-nostdinc++",
        "-isystem",
        "%s/libcxx-macos-%s/include/c++/v1" % (TOOLCHAIN_PREFIX, arch),
    ]

def libcxx_link_flags(arch):
    """The from-source static libc++/libc++abi, and nothing exported.

    libSystem, and the unwinder in it, is linked dynamically: macOS allows
    nothing else, so there is no counterpart of Linux's -static-pie,
    --rtlib or --unwindlib here. -nostdlib++ in place of Linux's
    -stdlib=libc++: libc++ is already the default on macOS, and this keeps
    clang from adding a -lc++ of its own, leaving link_libs the only one.

    -L puts our libc++ ahead of the SDK's: lld looks through the search
    paths in order, each for .tbd, .dylib or .a (lld/MachO/Driver.cpp,
    findLibrary), and this directory holds only libc++.a, so -lc++ cannot
    resolve to the SDK's libc++.tbd. CI's otool check fails the build if it
    ever does.

    -no_exported_symbols: a macOS executable otherwise exports every global
    symbol to dyld, here the whole of the static libc++ -- for quictun_client
    a 167KB export trie, plus the weak-binding entries that exporting brings.
    quictun loads no plugins, so like a Linux static-pie it exports nothing;
    lld documents the flag for exactly this ("main executables that don't
    have plugins"), after ld64.
    """
    return [
        "-nostdlib++",
        "-fuse-ld=lld",
        "-Wl,-no_exported_symbols",
        "-L%s/libcxx-macos-%s/lib" % (TOOLCHAIN_PREFIX, arch),
    ]

def libcxx_link_libs():
    return ["-lc++", "-lc++abi"]
