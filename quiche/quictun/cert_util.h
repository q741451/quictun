// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUICTUN_CERT_UTIL_H_
#define QUICHE_QUICTUN_CERT_UTIL_H_

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/proof_source.h"

namespace quictun {

// Ensures a self-signed EC (P-256) certificate and private key exist at
// `cert_path`/`key_path` (PEM), generating them if either file is missing.
//
// quictun has no PKI: like kcptun, trust comes entirely from the pre-shared
// key (see quictun_auth.h), not from certificate validation -- the client
// uses quic::FakeProofVerifier and skips CA checks. This certificate exists
// only because QUIC/TLS 1.3 requires *a* certificate to run at all; its
// identity is not meaningful and it is regenerated (not reused across
// installs) purely for operator convenience, so quictun-server works out of
// the box the same way kcptun-server does.
absl::Status EnsureSelfSignedCert(absl::string_view cert_path,
                                  absl::string_view key_path);

// Combines EnsureSelfSignedCert() with loading the resulting PEM files into
// a quic::ProofSource, ready to hand to quic::QuicServer.
absl::StatusOr<std::unique_ptr<quic::ProofSource>> LoadOrCreateProofSource(
    absl::string_view cert_path, absl::string_view key_path);

}  // namespace quictun

#endif  // QUICHE_QUICTUN_CERT_UTIL_H_
