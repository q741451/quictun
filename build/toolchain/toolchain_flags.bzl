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

# Static, but PIE only where PIE actually works.
#
# mipsel is -static rather than -static-pie because clang miscompiles
# -static-pie for that target: LLVM issue #124681, open since January 2025.
# The generated startup jumps to an address that is not on an instruction
# boundary, so the process dies with SIGILL before main() -- confirmed on a
# real MT7620 (MIPS 24KEc) router, where a -static-pie hello-world faults
# with or without RELR packing and the -static build of the same source runs.
# The issue is still open; -static is the only configuration observed to
# work, and is what this table selects until that changes.
#
# Sparse on purpose, and read with .get(): every architecture not listed is
# -static-pie, which is both the default and the desirable case. That is the
# opposite of ARCH_TARGET_FLAGS in toolchain_def.bzl, which is indexed
# strictly because it is *generated* and always complete, so a missing key
# there means a stale file. Do not "harmonise" the two -- making this one
# strict would break the four architectures that legitimately have no entry.
#
# This split existed before the musl migration, for a different reason:
# cross-glibc shipped no rcrt1.o for armhf or mipsel. Removing it was
# justified with "musl ships rcrt1.o on every architecture, so -static-pie
# works uniformly" -- which quietly equated "the startup object exists" with
# "the startup code is correct", and mipsel is exactly where those differ.
# Nothing caught it because nothing ran a mipsel binary on mipsel hardware.
#
# The cost on mipsel is ASLR: a non-PIE executable loads at a fixed address.
# A binary that runs without ASLR beats one that does not run.
_STATIC_MODE = {
    "mipsel": "-static",
}

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
        _STATIC_MODE.get(arch, "-static-pie"),
        "-L%s/libcxx-%s/lib" % (TOOLCHAIN_PREFIX, arch),
    ]

def libcxx_link_libs():
    return ["-lc++", "-lc++abi", "-lunwind"]
