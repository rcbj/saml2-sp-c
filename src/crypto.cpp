// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <zlib.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace iya::saml {
namespace {

struct Bio {
  BIO* bio = nullptr;
  explicit Bio(BIO* b) : bio(b) {}
  ~Bio() { BIO_free(bio); }
  Bio(const Bio&) = delete;
};

std::string bio_string(BIO* bio) {
  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  if (len < 0 || data == nullptr) return "";
  return std::string(data, static_cast<size_t>(len));
}

const EVP_MD* md_by_name(const std::string& name) {
  if (name == "sha1" || name == "SHA1") return EVP_sha1();
  if (name == "sha384" || name == "SHA384") return EVP_sha384();
  if (name == "sha512" || name == "SHA512") return EVP_sha512();
  return EVP_sha256();
}

std::string bn_param(EVP_PKEY* key, const char* name) {
  BIGNUM* bn = nullptr;
  if (EVP_PKEY_get_bn_param(key, name, &bn) != 1 || bn == nullptr) return "";
  std::string out(static_cast<size_t>(BN_num_bytes(bn)), '\0');
  BN_bn2bin(bn, reinterpret_cast<unsigned char*>(out.data()));
  BN_free(bn);
  return out;
}

}  // namespace

OwnedKey load_private_key(const std::string& pem) {
  Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio.bio) throw Failure("config", "the private key or certificate cannot be read: no PEM block");
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.bio, nullptr, nullptr, nullptr);
  if (!key) throw Failure("config", "the private key or certificate cannot be read: unrecognized private key");
  return OwnedKey(key);
}

OwnedCert load_certificate(const std::string& pem) {
  Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio.bio) throw Failure("config", "the private key or certificate cannot be read: no PEM block");
  X509* cert = PEM_read_bio_X509(bio.bio, nullptr, nullptr, nullptr);
  if (!cert) throw Failure("config", "the private key or certificate cannot be read: no PEM block");
  return OwnedCert(cert);
}

std::string certificate_to_pem(X509* cert) {
  Bio bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(bio.bio, cert)) throw Failure("config", "the certificate cannot be written");
  return bio_string(bio.bio);
}

std::string private_key_to_pem(EVP_PKEY* key) {
  Bio bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_PrivateKey(bio.bio, key, nullptr, nullptr, 0, nullptr, nullptr)) throw Failure("config", "the private key cannot be written");
  return bio_string(bio.bio);
}

std::string certificate_der_b64(X509* cert) {
  int len = i2d_X509(cert, nullptr);
  if (len <= 0) throw Failure("config", "the certificate cannot be written");
  std::string der(static_cast<size_t>(len), '\0');
  unsigned char* p = reinterpret_cast<unsigned char*>(der.data());
  i2d_X509(cert, &p);
  return b64_encode(der);
}

std::string rsa_kind(EVP_PKEY* key) {
  int id = EVP_PKEY_get_id(key);
  if (id == EVP_PKEY_RSA) return "";
  if (id == EVP_PKEY_EC) return "ec";
  if (id == EVP_PKEY_ED25519) return "ed25519";
  const char* name = EVP_PKEY_get0_type_name(key);
  return name ? name : "unknown";
}

bool same_rsa_public(EVP_PKEY* key, X509* cert) {
  if (EVP_PKEY_get_id(key) != EVP_PKEY_RSA) return false;
  OwnedKey pub(X509_get_pubkey(cert));
  if (!pub.key || EVP_PKEY_get_id(pub.key) != EVP_PKEY_RSA) return false;
  std::string n1 = bn_param(key, "n");
  std::string n2 = bn_param(pub.key, "n");
  std::string e1 = bn_param(key, "e");
  std::string e2 = bn_param(pub.key, "e");
  return !n1.empty() && n1 == n2 && e1 == e2;
}

std::string fingerprint_sha256(X509* cert) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (X509_digest(cert, EVP_sha256(), md, &len) != 1) throw Failure("config", "the certificate cannot be written");
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned int i = 0; i < len; i++) {
    if (i) out.push_back(':');
    out.push_back(hex[md[i] >> 4]);
    out.push_back(hex[md[i] & 0xF]);
  }
  return out;
}

std::string valid_to_text(X509* cert) {
  const ASN1_TIME* when = X509_get0_notAfter(cert);
  struct tm tm {};
  if (!ASN1_TIME_to_tm(when, &tm)) throw Failure("config", "the certificate cannot be written");
  static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  char buf[64];
  std::snprintf(buf, sizeof buf, "%s %02d %02d:%02d:%02d %04d GMT", months[tm.tm_mon], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_year + 1900);
  std::string text(buf);
  std::string replaced;
  for (size_t i = 0; i < text.size(); i++) {
    if (i + 1 < text.size() && text[i] == ' ' && text[i + 1] == '0') {
      replaced += "  ";
      i++;
    } else {
      replaced.push_back(text[i]);
    }
  }
  return replaced;
}

KeyPair make_key_pair(const std::string& common_name, int days, int bits) {
  if (days <= 0) days = 1095;
  if (bits == 0) bits = 3072;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) throw Failure("config", "the key could not be generated");
  OwnedKey key;
  if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1 || EVP_PKEY_keygen(ctx, &key.key) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw Failure("config", "the key could not be generated");
  }
  EVP_PKEY_CTX_free(ctx);
  OwnedCert cert(X509_new());
  if (!cert.cert) throw Failure("config", "the certificate could not be generated");
  X509_set_version(cert.cert, 2);
  unsigned char serial[16];
  RAND_bytes(serial, sizeof serial);
  serial[0] &= 0x7F;
  BIGNUM* bn = BN_bin2bn(serial, sizeof serial, nullptr);
  BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert.cert));
  BN_free(bn);
  X509_gmtime_adj(X509_getm_notBefore(cert.cert), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert.cert), static_cast<long>(days) * 24L * 60L * 60L - 60L);
  X509_NAME* name = X509_get_subject_name(cert.cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name.c_str()), -1, -1, 0);
  X509_set_issuer_name(cert.cert, name);
  X509_set_pubkey(cert.cert, key.key);
  X509_EXTENSION* usage = nullptr;
  X509V3_CTX v3;
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, cert.cert, cert.cert, nullptr, nullptr, 0);
  usage = X509V3_EXT_conf_nid(nullptr, &v3, NID_key_usage, "digitalSignature,keyEncipherment");
  if (usage) {
    X509_add_ext(cert.cert, usage, -1);
    X509_EXTENSION_free(usage);
  }
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, NID_ext_key_usage, "serverAuth,clientAuth");
  if (ext) {
    X509_add_ext(cert.cert, ext, -1);
    X509_EXTENSION_free(ext);
  }
  X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &v3, NID_basic_constraints, "critical,CA:FALSE");
  if (bc) {
    X509_add_ext(cert.cert, bc, -1);
    X509_EXTENSION_free(bc);
  }
  if (X509_sign(cert.cert, key.key, EVP_sha256()) == 0) throw Failure("config", "the certificate could not be generated");
  KeyPair pair;
  pair.private_key_pem = private_key_to_pem(key.key);
  pair.certificate_pem = certificate_to_pem(cert.cert);
  pair.fingerprint_sha256 = fingerprint_sha256(cert.cert);
  pair.valid_to = valid_to_text(cert.cert);
  return pair;
}

std::string b64_encode(const unsigned char* data, size_t len) {
  if (len == 0) return "";
  std::string out(((len + 2) / 3) * 4, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(len));
  if (n < 0) throw Failure("binding", "base64 failed");
  out.resize(static_cast<size_t>(n));
  return out;
}

std::string b64_encode(const std::string& data) { return b64_encode(reinterpret_cast<const unsigned char*>(data.data()), data.size()); }

std::string b64_decode(const std::string& in) {
  if (in.empty()) return "";
  std::string out((in.size() / 4) * 3 + 3, '\0');
  int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()), reinterpret_cast<const unsigned char*>(in.data()), static_cast<int>(in.size()));
  if (n < 0) throw Failure("binding", "base64 failed");
  int pad = 0;
  if (!in.empty() && in.back() == '=') pad++;
  if (in.size() > 1 && in[in.size() - 2] == '=') pad++;
  n -= pad;
  if (n < 0) n = 0;
  out.resize(static_cast<size_t>(n));
  return out;
}

std::string b64url_encode(const unsigned char* data, size_t len) {
  std::string out = b64_encode(data, len);
  for (char& c : out) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

std::string b64url_encode(const std::string& data) { return b64url_encode(reinterpret_cast<const unsigned char*>(data.data()), data.size()); }

std::string b64url_decode(const std::string& in, const std::string& what) {
  for (char c : in) {
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) throw Failure("signature", "the SET's " + what + " is not base64url");
  }
  std::string padded = in;
  for (char& c : padded) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (padded.size() % 4) padded.push_back('=');
  try {
    return b64_decode(padded);
  } catch (...) {
    throw Failure("signature", "the SET's " + what + " is not base64url");
  }
}

std::string sha256_raw(const std::string& data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
  return std::string(reinterpret_cast<char*>(md), len);
}

std::string sha1_raw(const std::string& data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha1(), nullptr);
  return std::string(reinterpret_cast<char*>(md), len);
}

std::string rsa_sign_pkcs1(EVP_PKEY* key, const std::string& data, const EVP_MD* md) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw Failure("signature", "the message could not be signed");
  size_t len = 0;
  if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, key) != 1 || EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1 ||
      EVP_DigestSignFinal(ctx, nullptr, &len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw Failure("signature", "the message could not be signed");
  }
  std::string out(len, '\0');
  if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(out.data()), &len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw Failure("signature", "the message could not be signed");
  }
  EVP_MD_CTX_free(ctx);
  out.resize(len);
  return out;
}

bool rsa_verify_pkcs1(EVP_PKEY* key, const std::string& data, const std::string& sig, const EVP_MD* md) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  int ok = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, key);
  if (ok == 1) ok = EVP_DigestVerifyUpdate(ctx, data.data(), data.size());
  if (ok == 1) ok = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
  EVP_MD_CTX_free(ctx);
  return ok == 1;
}

std::string rsa_oaep_decrypt(EVP_PKEY* key, const std::string& blob, const EVP_MD* md) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  if (!ctx) throw Failure("decryption", "the content key could not be unwrapped with this service provider's key");
  size_t len = 0;
  if (EVP_PKEY_decrypt_init(ctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1 || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) != 1 ||
      EVP_PKEY_decrypt(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(blob.data()), blob.size()) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw Failure("decryption", "the content key could not be unwrapped with this service provider's key");
  }
  std::string out(len, '\0');
  if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char*>(out.data()), &len, reinterpret_cast<const unsigned char*>(blob.data()), blob.size()) != 1) {
    EVP_PKEY_CTX_free(ctx);
    throw Failure("decryption", "the content key could not be unwrapped with this service provider's key");
  }
  EVP_PKEY_CTX_free(ctx);
  out.resize(len);
  return out;
}

std::string aes_gcm_decrypt(const std::string& key, const std::string& blob) {
  if (blob.size() < 12 + 16) throw Failure("decryption", "the ciphertext is too short");
  const EVP_CIPHER* cipher = nullptr;
  if (key.size() == 16) cipher = EVP_aes_128_gcm();
  else if (key.size() == 24) cipher = EVP_aes_192_gcm();
  else if (key.size() == 32) cipher = EVP_aes_256_gcm();
  else throw Failure("decryption", "the content could not be decrypted");
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw Failure("decryption", "the content could not be decrypted");
  std::string plain(blob.size(), '\0');
  int len = 0;
  int total = 0;
  const auto* iv = reinterpret_cast<const unsigned char*>(blob.data());
  const auto* ct = iv + 12;
  int ct_len = static_cast<int>(blob.size() - 12 - 16);
  const auto* tag = iv + 12 + ct_len;
  bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv) == 1 &&
            EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plain.data()), &len, ct, ct_len) == 1;
  total = len;
  if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) == 1;
  if (ok) ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plain.data()) + total, &len) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) throw Failure("decryption", "the content could not be decrypted");
  total += len;
  plain.resize(static_cast<size_t>(total));
  return plain;
}

std::string aes_cbc_decrypt(const std::string& key, const std::string& blob) {
  if (blob.size() < 32 || blob.size() % 16 != 0) throw Failure("decryption", "the ciphertext is not a whole number of blocks");
  const EVP_CIPHER* cipher = nullptr;
  if (key.size() == 16) cipher = EVP_aes_128_cbc();
  else if (key.size() == 24) cipher = EVP_aes_192_cbc();
  else if (key.size() == 32) cipher = EVP_aes_256_cbc();
  else throw Failure("decryption", "the content could not be decrypted");
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw Failure("decryption", "the content could not be decrypted");
  std::string plain(blob.size(), '\0');
  int len = 0;
  int total = 0;
  const auto* iv = reinterpret_cast<const unsigned char*>(blob.data());
  const auto* ct = iv + 16;
  int ct_len = static_cast<int>(blob.size() - 16);
  bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, reinterpret_cast<const unsigned char*>(key.data()), iv) == 1;
  if (ok) EVP_CIPHER_CTX_set_padding(ctx, 0);
  if (ok) ok = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plain.data()), &len, ct, ct_len) == 1;
  total = len;
  if (ok) ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plain.data()) + total, &len) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) throw Failure("decryption", "the content could not be decrypted");
  total += len;
  plain.resize(static_cast<size_t>(total));
  if (plain.empty()) throw Failure("decryption", "the decrypted content is not padded as XML Encryption pads it");
  unsigned char pad = static_cast<unsigned char>(plain.back());
  if (pad < 1 || pad > 16 || pad > plain.size()) throw Failure("decryption", "the decrypted content is not padded as XML Encryption pads it");
  for (size_t i = plain.size() - pad; i < plain.size(); i++) {
    if (static_cast<unsigned char>(plain[i]) != pad) throw Failure("decryption", "the decrypted content is not padded as XML Encryption pads it");
  }
  plain.resize(plain.size() - pad);
  return plain;
}

std::string deflate_raw(const std::string& data) {
  z_stream stream {};
  if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    throw Failure("binding", "the message could not be deflated");
  }
  stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
  stream.avail_in = static_cast<uInt>(data.size());
  std::string out;
  std::array<unsigned char, 4096> buf {};
  int rc = Z_OK;
  while (rc != Z_STREAM_END) {
    stream.next_out = buf.data();
    stream.avail_out = static_cast<uInt>(buf.size());
    rc = deflate(&stream, Z_FINISH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
      deflateEnd(&stream);
      throw Failure("binding", "the message could not be deflated");
    }
    out.append(reinterpret_cast<char*>(buf.data()), buf.size() - stream.avail_out);
  }
  deflateEnd(&stream);
  return out;
}

std::string inflate_raw(const std::string& data) {
  z_stream stream {};
  if (inflateInit2(&stream, -15) != Z_OK) throw Failure("binding", "the message inflates past the limit");
  stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
  stream.avail_in = static_cast<uInt>(data.size());
  std::string out;
  std::array<unsigned char, 4096> buf {};
  int rc = Z_OK;
  const size_t limit = 1024 * 1024;
  while (rc != Z_STREAM_END) {
    stream.next_out = buf.data();
    stream.avail_out = static_cast<uInt>(buf.size());
    rc = inflate(&stream, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
      inflateEnd(&stream);
      if (out.size() > limit) throw Failure("binding", "the message inflates past the limit");
      throw Failure("deflate", "inflate failed");
    }
    out.append(reinterpret_cast<char*>(buf.data()), buf.size() - stream.avail_out);
    if (out.size() > limit) {
      inflateEnd(&stream);
      throw Failure("binding", "the message inflates past the limit");
    }
  }
  inflateEnd(&stream);
  return out;
}

namespace {

bool pss_verify(EVP_PKEY* key, const EVP_MD* md, const std::string& data, const std::string& sig) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX* pctx = nullptr;
  if (!ctx) return false;
  bool ok = EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, key) == 1;
  if (ok) ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1;
  if (ok) ok = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1;
  if (ok) ok = EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1;
  if (ok) ok = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(sig.data()), sig.size()) == 1;
  EVP_MD_CTX_free(ctx);
  return ok;
}

std::string ecdsa_der(const std::string& sig, size_t size) {
  if (sig.size() != size * 2) return "";
  auto part = [&](const unsigned char* raw) {
    size_t start = 0;
    while (start + 1 < size && raw[start] == 0) start++;
    bool pad = (raw[start] & 0x80) != 0;
    std::string out;
    out.push_back(0x02);
    out.push_back(static_cast<char>(size - start + (pad ? 1 : 0)));
    if (pad) out.push_back(0);
    out.append(reinterpret_cast<const char*>(raw + start), size - start);
    return out;
  };
  std::string r = part(reinterpret_cast<const unsigned char*>(sig.data()));
  std::string s = part(reinterpret_cast<const unsigned char*>(sig.data() + size));
  std::string out;
  out.push_back(0x30);
  out.push_back(static_cast<char>(r.size() + s.size()));
  out += r;
  out += s;
  return out;
}

}  // namespace

bool jws_verify(EVP_PKEY* key, const std::string& alg, const std::string& data, const std::string& sig) {
  if (alg == "EdDSA" || alg == "Ed25519") {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    int ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key);
    if (ok == 1) ok = EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(sig.data()), sig.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size());
    EVP_MD_CTX_free(ctx);
    return ok == 1;
  }
  const EVP_MD* md = EVP_sha256();
  size_t ec_size = 32;
  bool pss = false;
  bool ec = false;
  if (alg == "RS256" || alg == "PS256" || alg == "ES256") md = EVP_sha256();
  if (alg == "RS384" || alg == "PS384" || alg == "ES384") {
    md = EVP_sha384();
    ec_size = 48;
  }
  if (alg == "RS512" || alg == "PS512" || alg == "ES512") {
    md = EVP_sha512();
    ec_size = 66;
  }
  if (alg.size() >= 2 && alg[0] == 'P') pss = true;
  if (alg.size() >= 2 && alg[0] == 'E') ec = true;
  if (pss) return pss_verify(key, md, data, sig);
  if (ec) {
    std::string der = ecdsa_der(sig, ec_size);
    if (der.empty()) return false;
    return rsa_verify_pkcs1(key, data, der, md);
  }
  return rsa_verify_pkcs1(key, data, sig, md);
}

OwnedKey jwk_to_key(const Json& jwk) {
  std::string kty = jwk.str_or("kty");
  std::string kid = jwk.str_or("kid");
  try {
    if (kty == "RSA") {
      std::string n = b64url_decode(jwk.str_or("n"), "key");
      std::string e = b64url_decode(jwk.str_or("e"), "key");
      BIGNUM* bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(n.data()), static_cast<int>(n.size()), nullptr);
      BIGNUM* be = BN_bin2bn(reinterpret_cast<const unsigned char*>(e.data()), static_cast<int>(e.size()), nullptr);
      OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_BN(bld, "n", bn);
      OSSL_PARAM_BLD_push_BN(bld, "e", be);
      OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
      EVP_PKEY* key = nullptr;
      if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      EVP_PKEY_CTX_free(ctx);
      BN_free(bn);
      BN_free(be);
      if (!key) throw Failure("signature", "the transmitter's key " + kid + " cannot be read: unsupported kty RSA");
      return OwnedKey(key);
    }
    if (kty == "EC") {
      std::string crv = jwk.str_or("crv");
      std::string curve = crv == "P-256" ? "P-256" : crv == "P-384" ? "P-384" : crv == "P-521" ? "P-521" : "";
      if (curve.empty()) throw Failure("signature", "the transmitter's key " + kid + " cannot be read: unsupported curve");
      std::string x = b64url_decode(jwk.str_or("x"), "key");
      std::string y = b64url_decode(jwk.str_or("y"), "key");
      unsigned char one = 0x04;
      std::string pub;
      pub.push_back(static_cast<char>(one));
      pub += x;
      pub += y;
      OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_utf8_string(bld, "group", curve.data(), curve.size());
      OSSL_PARAM_BLD_push_octet_string(bld, "pub", pub.data(), pub.size());
      OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
      EVP_PKEY* key = nullptr;
      if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      EVP_PKEY_CTX_free(ctx);
      if (!key) throw Failure("signature", "the transmitter's key " + kid + " cannot be read: unsupported curve");
      return OwnedKey(key);
    }
    if (kty == "OKP") {
      std::string x = b64url_decode(jwk.str_or("x"), "key");
      if (x.size() != 32) throw Failure("signature", "the transmitter's key " + kid + " cannot be read: bad OKP length");
      OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_octet_string(bld, "pub", x.data(), x.size());
      OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
      EVP_PKEY* key = nullptr;
      if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      EVP_PKEY_CTX_free(ctx);
      if (!key) throw Failure("signature", "the transmitter's key " + kid + " cannot be read: bad OKP length");
      return OwnedKey(key);
    }
  } catch (const Failure&) {
    throw;
  } catch (...) {
    throw Failure("signature", "the transmitter's key " + kid + " cannot be read: unsupported kty " + kty);
  }
  throw Failure("signature", "the transmitter's key " + kid + " cannot be read: unsupported kty " + kty);
}

}  // namespace iya::saml
