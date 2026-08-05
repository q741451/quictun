// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_certificate.h"

#include <memory>
#include <string>
#include <utility>

#include "quiche/quic/core/crypto/certificate_util.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/tools/simple_ticket_crypter.h"

namespace quic {

namespace {

// ProofSourceX509::GetTicketCrypter() returns nullptr by default -- without
// a TicketCrypter the server can never issue session tickets, so 0-RTT
// resumption is impossible no matter how the client is configured. This
// wraps it with a SimpleTicketCrypter (quiche/quic/tools/simple_ticket_crypter.h,
// otherwise only exercised by its own unit test) to make ticket issuance
// unconditional; --zero_rtt on quictun_client is what actually decides
// whether resumption is attempted.
class QuictunProofSource : public ProofSourceX509 {
 public:
  QuictunProofSource(quiche::QuicheReferenceCountedPointer<Chain> chain,
                     CertificatePrivateKey key)
      : ProofSourceX509(std::move(chain), std::move(key)),
        ticket_crypter_(QuicDefaultClock::Get()) {}

  TicketCrypter* GetTicketCrypter() override { return &ticket_crypter_; }

 private:
  SimpleTicketCrypter ticket_crypter_;
};

}  // namespace

std::unique_ptr<ProofSource> MakeQuictunSelfSignedProofSource() {
  CertificatePrivateKey key(MakeKeyPairForSelfSignedCertificate());

  // Validity window is arbitrary and wide: the client never checks it (or
  // any other part of the chain -- see the file comment), so there's
  // nothing to gain from computing "now" precisely, and a fixed window
  // avoids any startup-time clock dependency.
  CertificateOptions options;
  options.subject = "CN=quictun";
  options.serial_number = 1;
  options.validity_start = {2020, 1, 1, 0, 0, 0};
  options.validity_end = {2049, 12, 31, 0, 0, 0};
  std::string der_cert = CreateSelfSignedCertificate(*key.private_key(), options);

  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain(
      new ProofSource::Chain({der_cert}));

  auto proof_source =
      std::make_unique<QuictunProofSource>(chain, std::move(key));
  return proof_source;
}

}  // namespace quic
