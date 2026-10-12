// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_poll_event_loop.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_alarm_factory_proxy.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

// On Linux, use eventfd(2) to implement QuicEventLoop::WakeUp() API.
// The API in question is not implemented on other QUICHE-supported platforms.
// libevent supports this on other platforms, and should be used if such
// functionality is required.
#if defined(__linux__)
#include <sys/eventfd.h>
#define QUIC_SUPPORTS_EVENTFD 1
#else
#define QUIC_SUPPORTS_EVENTFD 0
#endif  // defined(__linux__)

namespace quic {

namespace {

using PollMask = decltype(::pollfd().events);

#if defined(_WIN32)
// WSAPoll()'s POLLIN is POLLRDNORM | POLLRDBAND, and POLLRDBAND reports a TCP
// urgent byte, which recv() without MSG_OOB never consumes: asking for POLLIN
// would let one urgent byte from a peer wake the loop forever. POLLRDNORM is
// normal data alone -- what POLLIN means on Linux, and all Chromium waits for
// (FD_READ, never FD_OOB, in net/socket/tcp_socket_win.cc). The urgent byte
// is skipped by recv(), as on Linux.
constexpr PollMask kPollReadable = POLLRDNORM;
#else
constexpr PollMask kPollReadable = POLLIN;
#endif

PollMask GetPollMask(QuicSocketEventMask event_mask) {
  return ((event_mask & kSocketEventReadable) ? kPollReadable : 0) |
         ((event_mask & kSocketEventWritable) ? POLLOUT : 0) |
         ((event_mask & kSocketEventError) ? POLLERR : 0);
}

QuicSocketEventMask GetEventMask(PollMask poll_mask) {
  return ((poll_mask & kPollReadable) ? kSocketEventReadable : 0) |
         ((poll_mask & POLLOUT) ? kSocketEventWritable : 0) |
         ((poll_mask & POLLERR) ? kSocketEventError : 0);
}

#if QUIC_SUPPORTS_EVENTFD
class QuicPollEventLoopDrainListener : public QuicSocketEventListener {
 public:
  void OnSocketEvent(QuicEventLoop* loop, SocketFd fd,
                     QuicSocketEventMask event) override {
    QUICHE_DCHECK_EQ(event, kSocketEventReadable);
    // eventfd_read will reset the associated event counter to zero.
    eventfd_t value;
    int result = eventfd_read(fd, &value);
    QUIC_BUG_IF(QuicPollEventLoopDrainListener_read_failed, result != 0)
        << "eventfd_read call failed: " << errno;
    // Rearm the `fd`, since the poll-based loop is level-triggered.
    bool success = loop->RearmSocket(fd, kSocketEventReadable);
    QUICHE_DCHECK(success);
  }
};
#endif

}  // namespace

QuicPollEventLoop::QuicPollEventLoop(QuicClock* clock) : clock_(clock) {
#if QUIC_SUPPORTS_EVENTFD
  static absl::NoDestructor<QuicPollEventLoopDrainListener>
      poll_event_loop_drain_listener;
  wake_up_eventfd_ = OwnedSocketFd(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
  bool success = RegisterSocket(wake_up_eventfd_.get(), kSocketEventReadable,
                                poll_event_loop_drain_listener.get());
  QUICHE_DCHECK(success);
#endif
}

bool QuicPollEventLoop::RegisterSocket(SocketFd fd, QuicSocketEventMask events,
                                       QuicSocketEventListener* listener) {
  auto [it, success] =
      registrations_.insert({fd, std::make_shared<Registration>()});
  if (!success) {
    return false;
  }
  Registration& registration = *it->second;
  registration.events = events;
  registration.listener = listener;
  return true;
}

bool QuicPollEventLoop::UnregisterSocket(SocketFd fd) {
  return registrations_.erase(fd);
}

bool QuicPollEventLoop::RearmSocket(SocketFd fd, QuicSocketEventMask events) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    return false;
  }
  it->second->events |= events;
  return true;
}

bool QuicPollEventLoop::ArtificiallyNotifyEvent(SocketFd fd,
                                                QuicSocketEventMask events) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    return false;
  }
  has_artificial_events_pending_ = true;
  it->second->artificially_notify_at_next_iteration |= events;
  return true;
}

void QuicPollEventLoop::RunEventLoopOnce(QuicTime::Delta default_timeout) {
  const QuicTime start_time = clock_->Now();
  alarms_.ProcessAlarmsUpTo(start_time);

  QuicTime::Delta timeout = ComputePollTimeout(start_time, default_timeout);
  ProcessIoEvents(start_time, timeout);

  const QuicTime end_time = clock_->Now();
  alarms_.ProcessAlarmsUpTo(end_time);
}

QuicTime::Delta QuicPollEventLoop::ComputePollTimeout(
    QuicTime now, QuicTime::Delta default_timeout) const {
  default_timeout = std::max(default_timeout, QuicTime::Delta::Zero());
  if (has_artificial_events_pending_) {
    return QuicTime::Delta::Zero();
  }
  std::optional<QuicTime> next_alarm = alarms_.GetNextUpcomingAlarm();
  if (!next_alarm.has_value()) {
    return default_timeout;
  }
  QuicTime end_time = std::min(now + default_timeout, *next_alarm);
  if (end_time < now) {
    // We only run a single pass of processing alarm callbacks per
    // RunEventLoopOnce() call.  If an alarm schedules another alarm in the past
    // while in the callback, this will happen.
    return QuicTime::Delta::Zero();
  }
  return end_time - now;
}

int QuicPollEventLoop::PollWithRetries(absl::Span<pollfd> fds,
                                       QuicTime start_time,
                                       QuicTime::Delta timeout) {
  const QuicTime timeout_at = start_time + timeout;
  int poll_result;
  for (;;) {
    float timeout_ms = std::ceil(timeout.ToMicroseconds() / 1000.f);
    poll_result =
        PollSyscall(fds.data(), fds.size(), static_cast<int>(timeout_ms));

#if !defined(_WIN32)
    // Nothing is dispatched after a failed poll(), and nothing about the next
    // call would differ, so the loop would spin without a trace. The ways it
    // can fail besides EINTR (EFAULT, EINVAL, ENOMEM) are a bug or a system
    // out of memory; neither is something to carry on through. PollSyscall()
    // fails loudly itself on Windows, where the error is not in errno.
    if (poll_result < 0 && errno != EINTR) {
      const int error = errno;
      QUICHE_LOG(FATAL) << "poll() failed on " << fds.size()
                        << " sockets: " << strerror(error);
    }
#endif
    // Stop if there are events or a non-EINTR error.
    bool done = poll_result > 0 || (poll_result < 0 && errno != EINTR);
    if (done) {
      break;
    }
    // Poll until `clock_` shows the timeout was exceeded.
    // PollSyscall uses a system clock internally that may run faster.
    QuicTime now = clock_->Now();
    if (now >= timeout_at) {
      break;
    }
    timeout = timeout_at - now;
  }
  return poll_result;
}

void QuicPollEventLoop::ProcessIoEvents(QuicTime start_time,
                                        QuicTime::Delta timeout) {
  // Set up the pollfd[] array.
  const size_t registration_count = registrations_.size();
  auto pollfds = std::make_unique<pollfd[]>(registration_count);
  size_t i = 0;
  for (auto& [fd, registration] : registrations_) {
    // Nothing armed means nothing can be delivered: poll(2) reports
    // POLLERR, POLLHUP and POLLNVAL whether or not they were requested,
    // but DispatchIoEvent() masks away whatever the registration did not
    // ask for and returns having called nothing -- yet poll() has already
    // returned non-zero, so the loop does not sleep. POLLHUP makes that
    // permanent: GetEventMask() has no mapping for it at all, and only
    // closing the socket clears it, so one hung-up socket pins a core for
    // as long as it stays open. Idle-but-registered is the ordinary state
    // of a socket here (see EventLoopConnectingClientSocket::Open()).
    if (registration->events == 0 &&
        registration->artificially_notify_at_next_iteration == 0) {
      continue;
    }
    QUICHE_CHECK_LT(
        i, registration_count);  // Crash instead of out-of-bounds access.
    pollfds[i].fd = fd;
    pollfds[i].events = GetPollMask(registration->events);
    pollfds[i].revents = 0;
    ++i;
  }
  const size_t polled_count = i;

  // Actually run poll(2).
  int poll_result =
      PollWithRetries(absl::Span<pollfd>(pollfds.get(), polled_count),
                      start_time, timeout);
  if (poll_result == 0 && !has_artificial_events_pending_) {
    return;
  }

  // Prepare the list of all callbacks to be called, while resetting all events,
  // since we're operating in the level-triggered mode.
  std::vector<ReadyListEntry> ready_list;
  ready_list.reserve(polled_count);
  for (i = 0; i < polled_count; i++) {
    DispatchIoEvent(ready_list, pollfds[i].fd, pollfds[i].revents);
  }
  has_artificial_events_pending_ = false;

  if (poll_result > 0 && ready_list.empty()) {
    // poll() returned, but only with conditions nobody was waiting for: an
    // unsubscribed POLLERR (6990cb05d's 100% CPU), or WSAPoll()'s POLLHUP on
    // a socket whose reader has already seen EOF (see DispatchIoEvent()).
    // Such a condition stays until something consumes it or the socket is
    // closed, so the next poll() would return at once too and the loop spin.
    // Wait 1ms first instead: whoever is waiting on the socket is still woken
    // by its own event, at most 1ms late, and no core is pinned meanwhile.
    // Logged at ERROR, the lowest level shown by default, except for the one
    // case that is expected: WSAPoll()'s POLLHUP alone.
    for (i = 0; i < polled_count; i++) {
#if defined(_WIN32)
      if (pollfds[i].revents == POLLHUP) {
        continue;
      }
#endif
      if (pollfds[i].revents != 0) {
        QUICHE_LOG_EVERY_N_SEC(ERROR, 60)
            << "poll() reported only unrequested events (fd " << pollfds[i].fd
            << ", events 0x" << std::hex << pollfds[i].events << ", revents 0x"
            << pollfds[i].revents << std::dec << "); waiting 1ms before the "
            << "next poll() so that this does not spin";
        break;
      }
    }
    absl::SleepFor(absl::Milliseconds(1));
  }

  // Actually call all of the callbacks.
  RunReadyCallbacks(ready_list);
}

void QuicPollEventLoop::DispatchIoEvent(std::vector<ReadyListEntry>& ready_list,
                                        SocketFd fd, PollMask mask) {
  auto it = registrations_.find(fd);
  if (it == registrations_.end()) {
    QUIC_BUG(poll returned an unregistered fd) << fd;
    return;
  }
  Registration& registration = *it->second;

  mask |= GetPollMask(registration.artificially_notify_at_next_iteration);
#if defined(_WIN32)
  // WSAPoll() reports POLLHUP as soon as the peer has shut down its sending
  // side, and keeps reporting it, requested or not, until the socket is
  // closed. Linux reports that as readable (EOF), and so do wepoll and libuv
  // on Windows (AFD_POLL_DISCONNECT -> EPOLLIN | EPOLLRDHUP), so it wakes the
  // reader only. Waking the writer too, as below, would have it send into a
  // full buffer, get WSAEWOULDBLOCK and be woken again at once. A refused
  // connect() still reaches its waiter: since Windows 10 2004, the oldest
  // quictun runs on, it comes with POLLERR and POLLWRNORM as well.
  if (mask & POLLHUP) {
    mask |= kPollReadable;
  }
#elif !defined(__linux__)
  // A hang-up wakes everything that is waiting on the socket, as libevent's
  // poll backend (poll.c) and Chromium's epoll pump do: each callback then
  // reads, writes or collects its connect result and gets the real error.
  // macOS reports a refused non-blocking connect() as POLLHUP alone, which
  // GetEventMask() does not map and the masking below would drop; poll()
  // would then return at once forever and the loop spin, with the waiter
  // never learning the connect failed. Linux always reports POLLERR (and
  // POLLOUT) with it, so it does not need this.
  if (mask & POLLHUP) {
    mask |= GetPollMask(registration.events);
  }
#endif
  // poll() always returns certain classes of events even if not requested.
  mask &= GetPollMask(registration.events |
                      registration.artificially_notify_at_next_iteration);
  registration.artificially_notify_at_next_iteration = QuicSocketEventMask();
  if (!mask) {
    return;
  }

  ready_list.push_back(ReadyListEntry{fd, it->second, GetEventMask(mask)});
  registration.events &= ~GetEventMask(mask);
}

void QuicPollEventLoop::RunReadyCallbacks(
    std::vector<ReadyListEntry>& ready_list) {
  for (ReadyListEntry& entry : ready_list) {
    std::shared_ptr<Registration> registration = entry.registration.lock();
    if (!registration) {
      // The socket has been unregistered from within one of the callbacks.
      continue;
    }
    registration->listener->OnSocketEvent(this, entry.fd, entry.events);
  }
  ready_list.clear();
}

std::unique_ptr<QuicAlarmFactory> QuicPollEventLoop::CreateAlarmFactory() {
  return std::make_unique<QuicAlarmFactoryProxy>(&alarms_);
}

bool QuicPollEventLoop::SupportsWakeUp() const {
  return wake_up_eventfd_.valid();
}

void QuicPollEventLoop::WakeUp() {
#if QUIC_SUPPORTS_EVENTFD
  if (SupportsWakeUp()) {
    int result = eventfd_write(*wake_up_eventfd_, 1);
    QUIC_BUG_IF(QuicPollEventLoop_WakeUp_Failed, result != 0)
        << "eventfd_write call failed: " << errno;
    return;
  }
#endif

  QUIC_BUG(QuicPollEventLoop_WakeUp_Unimplemented)
      << "QuicPollEventLoop::WakeUp() is not supported on this platform";
}

int QuicPollEventLoop::PollSyscall(pollfd* fds, size_t nfds, int timeout) {
#if defined(_WIN32)
  // WSAPoll() accepts only POLLRDNORM, POLLRDBAND, POLLWRNORM and POLLPRI in
  // `events` and fails the whole call with WSAEINVAL on anything else; error
  // conditions are always reported in `revents` without being asked for
  // (Microsoft's WSAPoll documentation). POSIX likewise ignores POLLERR in
  // `events`, so dropping it here changes nothing that poll() would report.
  // nginx's ngx_win32_poll_module.c requests only POLLIN/POLLOUT for the
  // same reason.
  for (size_t i = 0; i < nfds; ++i) {
    fds[i].events &= ~POLLERR;
  }
  int result = WSAPoll(fds, static_cast<ULONG>(nfds), timeout);
  // Winsock reports its errors through WSAGetLastError(), not errno, and has
  // no EINTR to retry on, so the caller's errno check cannot see a failure:
  // it would dispatch nothing and poll again at once, forever. Fail loudly
  // instead, as nginx does (ngx_win32_poll_module.c: "WSAPoll() failed").
  if (result == SOCKET_ERROR) {
    QUICHE_LOG(FATAL) << "WSAPoll() failed with error " << WSAGetLastError()
                      << " on " << nfds << " sockets";
  }
  return result;
#else
  return ::poll(fds, nfds, timeout);
#endif  // defined(_WIN32)
}

}  // namespace quic
