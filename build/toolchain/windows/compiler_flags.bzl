"""The compiler flags the Windows toolchain applies, in clang-cl spelling.

The counterpart of build/toolchain/compiler_flags.bzl, item for item: the
same lists under the same names, each entry mapped from the GCC-driver flag
it stands for. Where a flag has no counterpart it is because COFF/Windows has
nothing it would change, as noted.

Constants only, like that file: it loads nothing.
"""

# C and C++ alike:
#   -fno-strict-aliasing        -> /clang:-fno-strict-aliasing
#   -fPIC                       -> nothing: COFF has no PIC model; images
#                                  are relocatable for ASLR (/DYNAMICBASE,
#                                  lld-link's default) regardless
#   -fvisibility=hidden         -> nothing: a COFF image exports only what
#                                  is marked dllexport, which is the same
#                                  outcome
#   -ffunction-sections         -> /Gy
#   -fdata-sections             -> /Gw
#   -fno-unique-section-names   -> nothing: ELF section naming only
#   (no stack protector)        -> /GS-. clang-cl turns stack cookies on by
#                                  default where the clang driver for Linux
#                                  and macOS leaves them off, and the list
#                                  there sets none; /GS- keeps the three
#                                  alike. /GS would cost ~12% of the code
#                                  (quic_connection.cc's .text).
#
# And how every translation unit sees <windows.h>, which has no POSIX
# counterpart: as Chromium's Windows builds do (build/config/BUILDCONFIG.gn's
# default_compiler_configs for is_win: lean_and_mean,
# wincrypt_use_symbol_prefix, unicode; nominmax comes from rules_cc's own
# defaults). Without them the headers' macros break QUICHE and BoringSSL:
# `interface` (combaseapi.h), an X509_NAME that collides with BoringSSL's
# (wincrypt.h). NOGDI as well: wingdi.h defines ERROR as 0, which turns
# QUICHE's QUICHE_LOG(ERROR) into an undefined QUICHE_LOG_IMPL_0. Chromium
# avoids it with its own logging; protobuf (port_def.inc) and abseil
# (mutex.cc) each #undef ERROR in their own files. NOGDI keeps wingdi.h out
# for every file, and nothing here draws anything.
COMPILE_FLAGS = [
    "/clang:-fno-strict-aliasing",
    "/Gy",
    "/Gw",
    "/GS-",
    "/DWIN32_LEAN_AND_MEAN",
    "/DWINCRYPT_USE_SYMBOL_PREFIX",
    "/DUNICODE",
    "/D_UNICODE",
    "/DNOGDI",
]

# C++ only:
#   -std=c++23                  -> /std:c++23preview, the same level, as
#                                  Chromium spells it for clang-cl
#                                  (build/config/compiler/BUILD.gn). Not
#                                  /clang:-std=c++23: clang-cl applies
#                                  /clang: flags after all others, so a
#                                  target's own copts could not lower it the
#                                  way googleurl's -std=c++20 does on Linux.
#   -fno-rtti                   -> /GR-
#   -fno-exceptions             -> /EHs-c- (overriding the /EHsc rules_cc
#                                  adds) and _HAS_EXCEPTIONS=0 for the CRT
#                                  headers, as Chromium's no_exceptions
#                                  config does on Windows
#   -fvisibility-inlines-hidden -> nothing, as -fvisibility=hidden above
CXX_FLAGS = [
    "/std:c++23preview",
    "/GR-",
    "/EHs-c-",
    "/D_HAS_EXCEPTIONS=0",
]

# Link:
#   -fPIC                       -> nothing, as above
LINK_FLAGS = []
