"""Shared flag-list helpers for the pinned clang cc_toolchains in this
directory's BUILD.bazel. See that file for the full rationale."""

load(":toolchain_paths.bzl", "TOOLCHAIN_PREFIX")

def sysroot_flags(arch):
    """Points clang at the from-source musl built by setup_toolchain.sh.

    Nothing is picked up from the build host: --sysroot replaces /usr/include
    and /usr/lib wholesale, which is the point -- see setup_toolchain.sh.
    """
    return ["--sysroot=%s/musl-%s" % (TOOLCHAIN_PREFIX, arch)]

def libcxx_compile_flags(arch):
    return [
        "-nostdinc++",
        "-isystem",
        "%s/libcxx-%s/include/c++/v1" % (TOOLCHAIN_PREFIX, arch),
    ]

def libcxx_link_flags(arch):
    """compiler-rt/libunwind rather than libgcc/libgcc_eh, on every arch.

    The Chromium clang package ships compiler-rt only under *-linux-gnu
    triples while everything here targets *-linux-musl; setup_toolchain.sh
    resolves that once by aliasing the musl triple onto the gnu one inside
    clang's resource directory, so a plain --rtlib=compiler-rt resolves and
    no explicit archive paths are needed here.
    """
    return [
        "-stdlib=libc++",
        "-fuse-ld=lld",
        "--rtlib=compiler-rt",
        "--unwindlib=libunwind",
        # setup_toolchain.sh configures musl with --disable-shared, so there
        # is no libc.so and no ld-musl-*.so.1 to be an ELF interpreter --
        # linking statically is the only thing that can work, not a release
        # tweak layered on top. It has to live here rather than as a CI
        # --linkopt because that flag doesn't reach the exec configuration:
        # host tools (protoc, the upb generators) would still come out
        # dynamically linked against a musl loader the build host doesn't
        # have, and die with a bare "No such file or directory".
        "-static-pie",
        "-L%s/libcxx-%s/lib" % (TOOLCHAIN_PREFIX, arch),
    ]

def libcxx_link_libs():
    return ["-lc++", "-lc++abi", "-lunwind"]
