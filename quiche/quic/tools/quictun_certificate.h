// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Auto-generates a self-signed TLS certificate for quictun_server, entirely
// in memory (no files on disk, regenerated fresh every server start). The
// client never validates this certificate's chain at all (see
// quictun_client_driver.cc's use of FakeProofVerifier) -- the real
// authentication boundary is the --key shared secret, checked as an
// application-layer preamble (see quictun_client_connection.cc /
// quictun_server_connection.cc). The certificate exists only because TLS
// structurally requires one; it carries no security meaning here.
//
// The returned ProofSource also issues session tickets (needed for 0-RTT
// resumption, --zero_rtt): plain ProofSourceX509::GetTicketCrypter()
// returns nullptr, which would silently make 0-RTT impossible however the
// client is configured, so this wraps it with a ticket crypter whose
// AES-GCM key is derived from `psk` (--key) via HKDF. That determinism is
// deliberate: quictun_server always binds its port with SO_REUSEPORT so
// several instances can share it (see quictun_server_driver.cc), and every
// instance started with the same --key derives the identical ticket key --
// so a 0-RTT ticket one instance issued still resumes when the kernel steers
// the next connection to a different instance, and survives a restart too.
// A random per-process key (QUICHE's SimpleTicketCrypter) could not. The
// trade-off is forward secrecy: the key lives as long as --key rather than
// rotating -- accepted for quictun (see the --key/--zero_rtt security model
// in README.md).

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/proof_source.h"

namespace quic {

std::unique_ptr<ProofSource> MakeQuictunSelfSignedProofSource(
    absl::string_view psk);

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_
