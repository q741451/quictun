#!/usr/bin/env bash
# Run a command inside the pinned builder image.
#
#   scripts/in-builder.sh bash build/toolchain/setup_toolchain.sh x64
#   scripts/in-builder.sh dpkg-query -W
#
# The image is defined by .github/builder/Dockerfile: Ubuntu 24.04 pinned by
# digest, its packages by an archive snapshot. Everything the Linux and
# Windows builds take from the system -- make, cmake, ninja, python3, file,
# bash, coreutils -- comes from it, so GitHub moving ubuntu-latest to a newer
# Ubuntu cannot reach the output. The compilers are not in it; they are the
# pinned toolchain under build/toolchain/out. Same arrangement as 115dav's
# scripts/in-builder.sh.
#
# CI runs whole steps in it with `shell: in-builder.sh bash ... {0}` (the
# job puts scripts/ on PATH): the runner writes the step's script under
# $RUNNER_TEMP, which is mounted below.

set -euo pipefail

readonly IMAGE=quictun-builder
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Built by every job instead of cached: with the base a digest and the
# packages a snapshot, a rebuild gives the same image. Quick when the layers
# are already there, as they are from a job's second call on.
docker build --quiet --tag "$IMAGE" "$root/.github/builder" >/dev/null

# Mounted at the paths they have outside, and run as their owner: the
# toolchain records its absolute paths (build/toolchain/toolchain_paths.bzl),
# Bazel keeps its output tree and the caches actions/cache restores under
# $HOME, and what the build leaves behind -- bazel-bin and everything it
# points to -- must stay usable by the steps that run outside. Bazel itself
# is the bazelisk the workflow installs, checksum-verified, in
# $RUNNER_TEMP/bin. --user has no /etc/passwd entry here, so USER is passed
# for Bazel to name its output root after, as it does outside.
exec docker run --rm \
	--user "$(id -u):$(id -g)" \
	--volume "$HOME:$HOME" \
	--volume "$root:$root" \
	${RUNNER_TEMP:+--volume "$RUNNER_TEMP:$RUNNER_TEMP"} \
	--workdir "$PWD" \
	--env HOME \
	--env USER="$(id -un)" \
	--env PATH="${RUNNER_TEMP:+$RUNNER_TEMP/bin:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
	--env RUNNER_TEMP \
	--env BAZELISK_HOME \
	--env TARGETS \
	"$IMAGE" "$@"
