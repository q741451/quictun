"""The compiler flags every quictun toolchain applies, in GCC-driver spelling.

They match Chromium's default compiler config (build/config/compiler/BUILD.gn
and build/config/BUILDCONFIG.gn's default_compiler_configs), which is what
BoringSSL and QUICHE are actually built with inside Chromium. They used to be
--copt/--cxxopt lines in .bazelrc; they live in the toolchains instead because
they are spelled for one compiler driver, and the Windows toolchain drives
clang as clang-cl, which ignores them (its counterparts, under the same
names, are in build/toolchain/windows/compiler_flags.bzl). The Linux and
macOS toolchains both load this file, so the two cannot drift apart.

Constants only: this file loads nothing, so loading it never pulls in a
toolchain_paths.bzl from another OS's setup.
"""

# C and C++ alike.
COMPILE_FLAGS = [
    # crbug.com/32204
    "-fno-strict-aliasing",
    # Position-independent code (is_linux/is_chromeos/is_android/is_fuchsia).
    "-fPIC",
    # Hidden visibility by default (build/config/gcc:symbol_visibility_hidden),
    # applied to all is_posix targets.
    "-fvisibility=hidden",
    # Put each function/global in its own section so unused ones can be
    # dropped at link time (common_optimize_on_cflags + --gc-sections). Only
    # ELF uses them; clang ignores them for Mach-O, whose linker dead-strips
    # by atom.
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-unique-section-names",
]

# C++ only.
CXX_FLAGS = [
    # Chromium builds at C++23 (use_cxx23=true as of chromium/src
    # build/config/c++/c++.gni), not C++20.
    "-std=c++23",
    # no_rtti / no_exceptions: part of default_compiler_configs on every
    # platform, unless a sanitizer build re-enables RTTI.
    "-fno-rtti",
    "-fno-exceptions",
    "-fvisibility-inlines-hidden",
]

# The link half of -fPIC.
LINK_FLAGS = [
    "-fPIC",
]
