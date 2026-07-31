// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quictun/cert_util.h"

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/asn1.h"
#include "openssl/bio.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"

namespace quictun {
namespace {

constexpr int kValidityDays = 3650;  // ~10 years; identity is not meaningful.

bool FileExists(absl::string_view path) {
  std::string path_str(path);
  FILE* f = fopen(path_str.c_str(), "rb");
  if (f == nullptr) return false;
  fclose(f);
  return true;
}

absl::Status GenerateAndWrite(absl::string_view cert_path,
                              absl::string_view key_path) {
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  bssl::UniquePtr<EC_KEY> ec_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (ec_key == nullptr || !EC_KEY_generate_key(ec_key.get()) ||
      !EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key.release())) {
    return absl::InternalError("failed to generate EC key");
  }

  bssl::UniquePtr<X509> cert(X509_new());
  X509_set_version(cert.get(), 2);  // X.509v3: 0-indexed, so 2 == v3.
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()),
                  60L * 60 * 24 * kValidityDays);
  X509_set_pubkey(cert.get(), pkey.get());

  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("quictun"),
                             -1, -1, 0);
  X509_set_issuer_name(cert.get(), name);

  // quiche's ProofSourceX509 indexes certificates by SubjectAltName and
  // expects an X.509v3 leaf; a v1 cert with no SAN fails to parse there
  // even though it's a perfectly valid certificate otherwise. The SAN value
  // itself is not security-relevant here -- see the class comment in
  // cert_util.h -- it just has to be present and syntactically valid.
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
  bssl::UniquePtr<X509_EXTENSION> san_ext(X509V3_EXT_nconf_nid(
      nullptr, &ctx, NID_subject_alt_name, "DNS:quictun.invalid"));
  if (san_ext == nullptr || !X509_add_ext(cert.get(), san_ext.get(), -1)) {
    return absl::InternalError("failed to add SubjectAltName extension");
  }

  if (!X509_sign(cert.get(), pkey.get(), EVP_sha256())) {
    return absl::InternalError("failed to self-sign certificate");
  }

  std::string cert_path_str(cert_path);
  std::string key_path_str(key_path);

  bssl::UniquePtr<BIO> cert_bio(
      BIO_new_file(cert_path_str.c_str(), "wb"));
  if (cert_bio == nullptr || !PEM_write_bio_X509(cert_bio.get(), cert.get())) {
    return absl::InternalError(
        absl::StrCat("failed to write certificate to ", cert_path));
  }

  bssl::UniquePtr<BIO> key_bio(BIO_new_file(key_path_str.c_str(), "wb"));
  if (key_bio == nullptr ||
      !PEM_write_bio_PrivateKey(key_bio.get(), pkey.get(), nullptr, nullptr, 0,
                                nullptr, nullptr)) {
    return absl::InternalError(
        absl::StrCat("failed to write private key to ", key_path));
  }
  return absl::OkStatus();
}

}  // namespace

absl::Status EnsureSelfSignedCert(absl::string_view cert_path,
                                  absl::string_view key_path) {
  if (FileExists(cert_path) && FileExists(key_path)) {
    return absl::OkStatus();
  }
  return GenerateAndWrite(cert_path, key_path);
}

absl::StatusOr<std::unique_ptr<quic::ProofSource>> LoadOrCreateProofSource(
    absl::string_view cert_path, absl::string_view key_path) {
  absl::Status ensured = EnsureSelfSignedCert(cert_path, key_path);
  if (!ensured.ok()) return ensured;

  std::string cert_path_str(cert_path);
  std::string key_path_str(key_path);

  std::ifstream cert_stream(cert_path_str, std::ios::binary);
  std::vector<std::string> certs =
      quic::CertificateView::LoadPemFromStream(&cert_stream);
  if (certs.empty()) {
    return absl::InternalError(
        absl::StrCat("failed to load certificate from ", cert_path));
  }

  std::ifstream key_stream(key_path_str, std::ios::binary);
  std::unique_ptr<quic::CertificatePrivateKey> private_key =
      quic::CertificatePrivateKey::LoadPemFromStream(&key_stream);
  if (private_key == nullptr) {
    return absl::InternalError(
        absl::StrCat("failed to load private key from ", key_path));
  }

  quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain> chain(
      new quic::ProofSource::Chain(certs));
  std::unique_ptr<quic::ProofSourceX509> proof_source =
      quic::ProofSourceX509::Create(chain, std::move(*private_key));
  if (proof_source == nullptr) {
    return absl::InternalError("failed to construct ProofSourceX509");
  }
  return proof_source;
}

}  // namespace quictun
