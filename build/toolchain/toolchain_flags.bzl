"""Shared flag-list helpers for the pinned Chromium-style cc_toolchains in
this directory's BUILD.bazel. See that file for the full rationale."""

def libcxx_compile_flags(arch):
    return [
        "-nostdinc++",
        "-isystem",
        "/opt/libcxx-%s/include/c++/v1" % arch,
    ]

def libcxx_link_flags(arch, mips_runtime = False):
    flags = [
        "-stdlib=libc++",
        "-fuse-ld=lld",
        "-L/opt/libcxx-%s/lib" % arch,
    ]
    if mips_runtime:
        # No Chromium compiler-rt for MIPS; fall back to the pinned
        # libgcc-10-dev-mipsel-cross package's runtime instead, and allow
        # its (GCC10-generation) crt objects' executable-stack requirement
        # that a modern default-strict ld.lld otherwise rejects.
        flags += ["--rtlib=libgcc", "--unwindlib=libgcc", "-Wl,-z,execstack"]
    else:
        flags += ["--rtlib=compiler-rt", "--unwindlib=libunwind"]
    return flags

def libcxx_link_libs(mips_runtime = False):
    libs = ["-lc++", "-lc++abi"]
    if mips_runtime:
        # 32-bit MIPS has no native 64-bit atomic instructions; absl's
        # flags SequenceLock (among others) needs libatomic's
        # __atomic_load_8/__atomic_store_8 helpers.
        libs.append("-latomic")
    else:
        libs.append("-lunwind")
    return libs
