# The system the Linux and Windows builds run on, defined here and nowhere
# else.
#
# The compilers are not in it: build/toolchain/setup_toolchain*.sh download
# Chromium's pinned clang and build musl and libc++ with it. What this image
# fixes is everything around them that the build still takes from the
# system -- make for musl; cmake, ninja and python3 for the LLVM runtimes,
# and binutils' objdump for compiler-rt's configuration of crtbegin.o;
# file, xz and curl in the scripts and CI steps; bash and coreutils under
# Bazel's genrules -- which used to come from GitHub's runner image and
# change whenever it did. The base is pinned by digest and the packages by
# an archive snapshot, so a rebuild gives the same image: every job builds
# it afresh rather than caching it. scripts/in-builder.sh runs commands in
# it, as 115dav's does.

# Ubuntu 24.04 LTS, the release ubuntu-latest ran when this file replaced
# it. A tag can be repointed by its publisher; a digest is the content. To
# move to a newer base, resolve its digest with:
#   docker buildx imagetools inspect ubuntu:24.04 | head -2
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

# Every package as the Ubuntu archive held it at this moment
# (https://snapshot.ubuntu.com). To move, set a later one. The build jobs
# print every package in the image with its version ("Builder image").
ARG SNAPSHOT=20261004T000000Z

RUN set -eux; \
	# The snapshot as the only source. ninja-build is in universe.
	rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
	printf '%s\n' \
		'Types: deb' \
		"URIs: https://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}/" \
		'Suites: noble noble-updates noble-security' \
		'Components: main universe' \
		'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
		> /etc/apt/sources.list.d/snapshot.sources; \
	# snapshot.ubuntu.com serves https only, and the base image has no CA
	# certificates to check its TLS certificate with. What apt installs is
	# checked regardless: against the archive's signed InRelease, with the
	# keyring the base image ships -- the same guarantee Ubuntu's default
	# plain-http sources rely on.
	echo 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";' \
		> /etc/apt/apt.conf.d/99snapshot-tls; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		ca-certificates curl xz-utils file make cmake ninja-build python3 binutils; \
	rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99snapshot-tls
