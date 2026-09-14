// Copyright 2026 The quictun Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quictun_certificate.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/aead.h"
#include "openssl/err.h"
#include "openssl/hkdf.h"
#include "openssl/rand.h"
#include "quiche/quic/core/crypto/certificate_util.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

namespace {

// A TicketCrypter whose AES-128-GCM key is derived deterministically from
// --key, so every server instance started with the same --key computes the
// identical key. That is what makes 0-RTT resumption survive both landing
// on a different SO_REUSEPORT instance than issued the ticket and a server
// restart -- SimpleTicketCrypter's random per-process key cannot (its own
// header says so). The cost is forward secrecy: the key lives as long as
// --key rather than rotating. Format: 16-byte random IV, then the AES-GCM
// seal (16-byte tag). No key epoch -- there is only ever the one key.
class SharedTicketCrypter : public ProofSource::TicketCrypter {
 public:
  static constexpr size_t kKeySize = 16;
  static constexpr size_t kIVSize = 16;
  static constexpr size_t kAuthTagSize = 16;

  explicit SharedTicketCrypter(absl::string_view psk) {
    uint8_t key[kKeySize];
    static constexpr absl::string_view kInfo = "quictun session ticket v1";
    if (!HKDF(key, sizeof(key), EVP_sha256(),
              reinterpret_cast<const uint8_t*>(psk.data()), psk.size(),
              /*salt=*/nullptr, /*salt_len=*/0,
              reinterpret_cast<const uint8_t*>(kInfo.data()), kInfo.size())) {
      QUIC_BUG(quictun_ticket_hkdf) << "HKDF for the session-ticket key failed";
    }
    EVP_AEAD_CTX_init(aead_ctx_.get(), EVP_aead_aes_128_gcm(), key, sizeof(key),
                      EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr);
  }

  size_t MaxOverhead() override { return kIVSize + kAuthTagSize; }

  std::vector<uint8_t> Encrypt(absl::string_view in,
                               absl::string_view encryption_key) override {
    QUICHE_DCHECK(encryption_key.empty());
    std::vector<uint8_t> out(in.size() + MaxOverhead());
    RAND_bytes(out.data(), kIVSize);
    size_t out_len;
    if (!EVP_AEAD_CTX_seal(aead_ctx_.get(), out.data() + kIVSize, &out_len,
                           out.size() - kIVSize, out.data(), kIVSize,
                           reinterpret_cast<const uint8_t*>(in.data()),
                           in.size(), nullptr, 0)) {
      return std::vector<uint8_t>();
    }
    out.resize(out_len + kIVSize);
    return out;
  }

  void Decrypt(
      absl::string_view in,
      std::shared_ptr<ProofSource::DecryptCallback> callback) override {
    callback->Run(DecryptToBytes(in));
  }

 private:
  // Not named Decrypt so it can't shadow the base's virtual Decrypt().
  std::vector<uint8_t> DecryptToBytes(absl::string_view in) {
    if (in.size() < kIVSize) {
      return std::vector<uint8_t>();
    }
    const uint8_t* input = reinterpret_cast<const uint8_t*>(in.data());
    std::vector<uint8_t> out(in.size() - kIVSize);
    size_t out_len;
    if (!EVP_AEAD_CTX_open(aead_ctx_.get(), out.data(), &out_len, out.size(),
                           input, kIVSize, input + kIVSize, in.size() - kIVSize,
                           nullptr, 0)) {
      // An undecryptable ticket is a normal, handled outcome (the server
      // just declines resumption). But the failed open leaves a BAD_DECRYPT
      // on BoringSSL's thread-local error queue, and left there it contaminates
      // the rest of the handshake into a hard QUIC_HANDSHAKE_FAILED instead of
      // a clean fall-back to 1-RTT -- exactly what wedges a client holding a
      // ticket this server cannot decrypt (e.g. one issued by a previous build
      // across an upgrade). SimpleTicketCrypter dodges this by short-circuiting
      // on its key-epoch byte before ever calling open; we have no epoch, so
      // clear the queue explicitly.
      ERR_clear_error();
      return std::vector<uint8_t>();
    }
    out.resize(out_len);
    return out;
  }

  bssl::ScopedEVP_AEAD_CTX aead_ctx_;
};

// ProofSourceX509::GetTicketCrypter() returns nullptr by default -- without
// a TicketCrypter the server can never issue session tickets, so 0-RTT
// resumption is impossible no matter how the client is configured. This
// wraps it with a SharedTicketCrypter (--key-derived, so cross-instance --
// see the header) to make ticket issuance unconditional; --zero_rtt on
// quictun_client is what actually decides whether resumption is attempted.
class QuictunProofSource : public ProofSourceX509 {
 public:
  QuictunProofSource(quiche::QuicheReferenceCountedPointer<Chain> chain,
                     CertificatePrivateKey key, absl::string_view psk)
      : ProofSourceX509(std::move(chain), std::move(key)),
        ticket_crypter_(psk) {}

  TicketCrypter* GetTicketCrypter() override { return &ticket_crypter_; }

 private:
  SharedTicketCrypter ticket_crypter_;
};

}  // namespace

std::unique_ptr<ProofSource> MakeQuictunSelfSignedProofSource(
    absl::string_view psk) {
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
      std::make_unique<QuictunProofSource>(chain, std::move(key), psk);
  return proof_source;
}

}  // namespace quic
