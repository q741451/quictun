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
// client is configured, so this wraps it with a SimpleTicketCrypter.

#ifndef QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_
#define QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_

#include <memory>

#include "quiche/quic/core/crypto/proof_source.h"

namespace quic {

std::unique_ptr<ProofSource> MakeQuictunSelfSignedProofSource();

}  // namespace quic

#endif  // QUICHE_QUIC_TOOLS_QUICTUN_CERTIFICATE_H_
