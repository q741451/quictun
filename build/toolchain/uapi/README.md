# Vendored kernel UAPI headers (`asm/`)

musl ships no `<linux/*>` or `<asm/*>` kernel UAPI headers at all, by design.
Most of what this project's dependencies reach for is architecture-independent
and is handled inline -- see `install_uapi_shims()` in `../setup_toolchain.sh`.
`<asm/*>` is not: it is the one part of the UAPI that genuinely differs per
architecture, so it is vendored here verbatim rather than transcribed.

Why vendored rather than hand-written, given it is only a handful of constants
today:

- **Adding a target must not require a discovery pass.** Hand-written shims are
  found by failure: add an architecture, watch the build break on a header
  nobody knew was needed, write it, push, wait for CI, repeat. With the real
  headers present, a new architecture needs no shim work at all.
- **A wrong value here is a crash, not a slowdown.** `asm/hwcap.h` drives CPU
  feature detection. A bit in the wrong place doesn't lose an optimisation --
  it runs an instruction the CPU doesn't implement, and the process dies with
  SIGILL on hardware a dev machine can't reproduce. (The hand-written version
  this replaced was already missing `HWCAP_CPUID`, which abseil actually reads.)

Only two of these headers are reached by the current build -- `asm/hwcap.h` on
aarch64 and `asm/sgidefs.h` on mips, both self-contained -- but pruning to just
those would reintroduce exactly the discovery problem above.

## Contents

| Path | Kernel `ARCH=` | Used by |
|---|---|---|
| `asm-x86/` | `x86` | x86_64 |
| `asm-arm64/` | `arm64` | arm64 |
| `asm-arm/` | `arm` | armv7 |
| `asm-mips/` | `mips` | mipsel |
| `asm-riscv/` | `riscv` | (not yet a build target) |
| `asm-loongarch/` | `loongarch` | (not yet a build target) |
| `asm-generic/` | — | shared; `asm/*` headers include it |

riscv and loongarch are present but unused: they cost ~200KB each and having
them here is what makes adding those targets a one-line change to
`setup_toolchain.sh` rather than another round trip through CI.

## Provenance

Generated from an unmodified upstream kernel tarball:

    linux-6.18.46.tar.xz
    sha256 f5d44b93808b02cc2969c5404ba081d97523719c9fd2ba2de6db318b4141cca0
    https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.46.tar.xz

6.18 is a longterm release; it is used here rather than something older
because newer trees carry UAPI for architectures that were still incomplete
earlier (loongarch in particular).

## Regenerating

To bump the kernel, or to add an architecture, run `./regenerate.sh` from this
directory. It downloads and checksum-verifies the tarball, runs the kernel's
own `make headers_install` for each architecture, and copies the results here.
Nothing in this directory is edited by hand.
