# quictun smoke tests, on every OS it is built for

Two plain Python scripts (standard library only) that run on Linux, macOS
and Windows alike. Linux is the reference: `QuicPollEventLoop` is written
against what Linux's `poll()` reports, so what matters on macOS and Windows
is where they differ from it.

| Script | Does |
| --- | --- |
| `smoke_test.py <dir>` | Runs the `quictun_server-*`/`quictun_client-*` binaries in `<dir>` on loopback through the cases that differ between the three systems or once pinned a core (half-close, urgent data, resets, a response tail after the target closes, running out of file descriptors, a server that goes away). Fails on broken data, and on either process using more than 20% of a core after a case. |
| `smoke_test.py <dir>`, as root | On Linux and macOS, run as root it runs only the `--user` cases, which need root: both binaries bind below 1024, switch to `nobody`, and carry a tunnel, including across a server that goes away and returns. |
| `poll_probe.py` | Prints what `poll()` (`WSAPoll()` on Windows) and `select()` report in those same cases, without quictun involved. Asserts nothing; compare it with Linux's output. |

In CI they are off by default. To run them, start the *Build* workflow by
hand (*Actions* tab, *Build*, *Run workflow*) with **smoke** ticked: the
same run builds the binaries and then tests them on Ubuntu 24.04 (x86_64),
macOS 15 (arm64 and Intel), and Windows Server 2022 and 2025. They use the
Python each runner image ships, which is fine for a test that builds
nothing.

Locally, against a build of your own:

```
bazel build -c opt --platforms=//build/toolchain:linux_x64 //quiche:quictun_client //quiche:quictun_server
mkdir -p /tmp/qt && cp bazel-bin/quiche/quictun_client /tmp/qt/quictun_client-linux-x86_64 \
  && cp bazel-bin/quiche/quictun_server /tmp/qt/quictun_server-linux-x86_64
python3 testing/smoke/smoke_test.py /tmp/qt
```

It listens on ports 24000-24002, 24100-24120 (UDP) and 24200-24270 on
loopback -- below every OS's ephemeral range, which its own connections
draw from -- and keeps the server and client logs in a temporary directory
it prints at the end.
