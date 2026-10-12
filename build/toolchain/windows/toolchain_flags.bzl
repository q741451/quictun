"""Shared flag-list helpers for the pinned clang cc_toolchains in this
directory's BUILD.bazel: the Windows counterparts of
build/toolchain/toolchain_flags.bzl.

One difference in shape: on Linux and macOS one clang driver both compiles
and links, so a single sysroot_flags() serves both steps. Here clang-cl
compiles and lld-link links, with different flag syntaxes, so the SDK is
split into sysroot_compile_flags() and sysroot_link_flags()."""

load(":toolchain_paths.bzl", "TOOLCHAIN_PREFIX", "WINDOWS_SDK_ARCHES", "WINSDK_DIR")

# The include directories of the MSVC CRT and the Windows SDK, as xwin lays
# them out (see setup_toolchain_windows.sh, which builds libc++ with the
# same list).
SDK_INCLUDE_DIRS = [
    WINSDK_DIR + "/crt/include",
    WINSDK_DIR + "/sdk/include/ucrt",
    WINSDK_DIR + "/sdk/include/um",
    WINSDK_DIR + "/sdk/include/shared",
]

def sysroot_compile_flags():
    """Points clang-cl at the pinned SDK and CRT headers, as system headers.

    Nothing is picked up from the build host: /imsvc is where clang-cl looks
    for what MSVC would find through %INCLUDE%. Joined to its directory, not
    a separate argument: in the response files Bazel passes, a separate
    /home/... would be read as an option of its own.
    """
    return ["/imsvc" + d for d in SDK_INCLUDE_DIRS]

def sysroot_link_flags(arch):
    """Points lld-link at the pinned SDK and CRT import/static libraries."""
    sdk_arch = WINDOWS_SDK_ARCHES[arch]
    return [
        "/LIBPATH:%s/crt/lib/%s" % (WINSDK_DIR, sdk_arch),
        "/LIBPATH:%s/sdk/lib/um/%s" % (WINSDK_DIR, sdk_arch),
        "/LIBPATH:%s/sdk/lib/ucrt/%s" % (WINSDK_DIR, sdk_arch),
    ]

def libcxx_compile_flags(arch):
    """The from-source libc++ headers, ahead of everything else.

    /external:I (clang-cl's -isystem) rather than /imsvc: libc++'s headers
    must be found before clang's own builtin ones and the CRT's, and /imsvc
    directories come after both. _CRT_STDIO_ISO_WIDE_SPECIFIERS as libc++
    itself was built with it: lld-link refuses to mix objects that disagree
    (/failifmismatch), as Chromium's Windows libc++ setup also has it.
    """
    return [
        "/clang:-nostdinc++",
        "/external:I%s/libcxx-windows-%s/include/c++/v1" % (TOOLCHAIN_PREFIX, arch),
        "/D_CRT_STDIO_ISO_WIDE_SPECIFIERS",
    ]

def libcxx_link_flags(arch):
    """The static libc++, on the static MSVC runtime (/MT, from .bazelrc).

    There is no libc++abi on Windows: vcruntime is the C++ ABI layer, as in
    Chromium's Windows build, so nothing here corresponds to Linux's
    --rtlib/--unwindlib.
    """
    return ["/LIBPATH:%s/libcxx-windows-%s/lib" % (TOOLCHAIN_PREFIX, arch)]

def libcxx_link_libs():
    """libc++, and libcpmt.lib for the __ExceptionPtr* functions libc++'s
    std::exception_ptr calls into on Windows (the static MSVC C++ runtime;
    msvcprt.lib would be its /MD counterpart)."""
    return ["libc++.lib", "libcpmt.lib"]
