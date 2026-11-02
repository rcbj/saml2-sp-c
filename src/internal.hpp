// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include "iya/saml.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <libxml/tree.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace iya::saml {

// XML namespace names and algorithm identifiers. They are compared and written
// into documents, never fetched; the W3C fixed the http:// ones, and an
// https:// spelling would be a different name that no peer recognises.
constexpr const char* kNsSamlp = "urn:oasis:names:tc:SAML:2.0:protocol";
constexpr const char* kNsSaml = "urn:oasis:names:tc:SAML:2.0:assertion";
constexpr const char* kNsMd = "urn:oasis:names:tc:SAML:2.0:metadata";
constexpr const char* kNsDsig = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char* kNsXenc = "http://www.w3.org/2001/04/xmlenc#";
constexpr const char* kNsXenc11 = "http://www.w3.org/2009/xmlenc11#";
constexpr const char* kNsSoap = "http://schemas.xmlsoap.org/soap/envelope/";

constexpr const char* kBindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
constexpr const char* kBindingPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
constexpr const char* kBindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
constexpr const char* kBindingSoap = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
constexpr const char* kStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
constexpr const char* kBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

constexpr const char* kExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
constexpr const char* kExcC14NComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
constexpr const char* kC14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
constexpr const char* kC14N10Comments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
constexpr const char* kEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char* kRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
constexpr const char* kRsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
constexpr const char* kRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
constexpr const char* kDigest256 = "http://www.w3.org/2001/04/xmlenc#sha256";
constexpr const char* kDigest384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
constexpr const char* kDigest512 = "http://www.w3.org/2001/04/xmlenc#sha512";
constexpr const char* kPollMethod = "urn:ietf:rfc:8936";
constexpr const char* kDefaultSubject = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
constexpr const char* kEmailNameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

struct Json {
  enum class Type { Null, Bool, Number, String, Array, Object };
  Type type = Type::Null;
  bool b = false;
  double num = 0;
  std::string text;
  std::vector<Json> items;
  std::vector<std::pair<std::string, Json>> fields;

  const Json* find(const std::string& key) const;
  bool has(const std::string& key) const;
  std::string str_or(const std::string& key) const;
};

Json parse_json(const std::string& text);
std::string json_dump(const Json& value);

struct OwnedKey {
  EVP_PKEY* key = nullptr;
  OwnedKey() = default;
  explicit OwnedKey(EVP_PKEY* k) : key(k) {}
  ~OwnedKey() { EVP_PKEY_free(key); }
  OwnedKey(const OwnedKey&) = delete;
  OwnedKey& operator=(const OwnedKey&) = delete;
  OwnedKey(OwnedKey&& other) noexcept : key(other.key) { other.key = nullptr; }
  OwnedKey& operator=(OwnedKey&& other) noexcept {
    if (this != &other) {
      EVP_PKEY_free(key);
      key = other.key;
      other.key = nullptr;
    }
    return *this;
  }
};

struct OwnedCert {
  X509* cert = nullptr;
  OwnedCert() = default;
  explicit OwnedCert(X509* c) : cert(c) {}
  ~OwnedCert() { X509_free(cert); }
  OwnedCert(const OwnedCert&) = delete;
  OwnedCert& operator=(const OwnedCert&) = delete;
  OwnedCert(OwnedCert&& other) noexcept : cert(other.cert) { other.cert = nullptr; }
  OwnedCert& operator=(OwnedCert&& other) noexcept {
    if (this != &other) {
      X509_free(cert);
      cert = other.cert;
      other.cert = nullptr;
    }
    return *this;
  }
};

OwnedKey load_private_key(const std::string& pem);
OwnedCert load_certificate(const std::string& pem);
std::string certificate_to_pem(X509* cert);
std::string private_key_to_pem(EVP_PKEY* key);
std::string certificate_der_b64(X509* cert);
std::string rsa_kind(EVP_PKEY* key);
bool same_rsa_public(EVP_PKEY* key, X509* cert);
std::string fingerprint_sha256(X509* cert);
std::string valid_to_text(X509* cert);
KeyPair make_key_pair(const std::string& common_name, int days, int bits);

std::string b64_encode(const unsigned char* data, size_t len);
std::string b64_encode(const std::string& data);
std::string b64_decode(const std::string& in);
std::string b64url_encode(const unsigned char* data, size_t len);
std::string b64url_encode(const std::string& data);
std::string b64url_decode(const std::string& in, const std::string& what);
std::string sha256_raw(const std::string& data);
std::string sha1_raw(const std::string& data);
std::string rsa_sign_pkcs1(EVP_PKEY* key, const std::string& data, const EVP_MD* md);
bool rsa_verify_pkcs1(EVP_PKEY* key, const std::string& data, const std::string& sig, const EVP_MD* md);
std::string rsa_oaep_decrypt(EVP_PKEY* key, const std::string& blob, const EVP_MD* md);
std::string aes_gcm_decrypt(const std::string& key, const std::string& blob);
std::string aes_cbc_decrypt(const std::string& key, const std::string& blob);
std::string deflate_raw(const std::string& data);
std::string inflate_raw(const std::string& data);
bool jws_verify(EVP_PKEY* key, const std::string& alg, const std::string& data, const std::string& sig);
OwnedKey jwk_to_key(const Json& jwk);

struct HttpResult {
  int status = 0;
  std::string content_type;
  std::string body;
};

struct TlsOpt {
  std::string ca;
  std::string cert;
  std::string key;
};

HttpResult http_send(const std::string& url, const std::string& method, const std::vector<std::pair<std::string, std::string>>& headers,
                     const std::string& body, const TlsOpt* tls, const std::string& code);

struct XmlDoc {
  xmlDocPtr doc = nullptr;
  explicit XmlDoc(xmlDocPtr d = nullptr) : doc(d) {}
  ~XmlDoc() {
    if (doc) xmlFreeDoc(doc);
  }
  XmlDoc(const XmlDoc&) = delete;
  XmlDoc& operator=(const XmlDoc&) = delete;
  XmlDoc(XmlDoc&& other) noexcept : doc(other.doc) { other.doc = nullptr; }
  XmlDoc& operator=(XmlDoc&& other) noexcept {
    if (this != &other) {
      if (doc) xmlFreeDoc(doc);
      doc = other.doc;
      other.doc = nullptr;
    }
    return *this;
  }
  xmlNodePtr root() const { return doc ? xmlDocGetRootElement(doc) : nullptr; }
};

XmlDoc parse_xml(const std::string& text, const std::string& what);
std::string serialize_xml(xmlNodePtr node);
std::string sign_enveloped(const std::string& xml, const std::string& element_id, EVP_PKEY* key, X509* cert);
std::string verify_signed(xmlNodePtr element, const std::vector<X509*>& certs, const std::string& what);
void assert_unique_ids(xmlNodePtr root);
bool same_element(xmlNodePtr el, const char* ns, const char* local);
std::vector<xmlNodePtr> child_elements(xmlNodePtr el, const char* ns, const char* local);
xmlNodePtr one_child(xmlNodePtr el, const char* ns, const char* local);
std::vector<xmlNodePtr> descendant_elements(xmlNodePtr el, const char* ns, const char* local);
std::string text_of(xmlNodePtr el);
std::string iter_text(xmlNodePtr el);
std::string attr_of(xmlNodePtr el, const char* name);
bool has_attr(xmlNodePtr el, const char* name);
std::string escape_xml(const std::string& value);
xmlNodePtr element_by_id(xmlNodePtr root, const std::string& id);
std::string pem_body(const std::string& pem);
std::string to_pem_cert(const std::string& b64);

struct ResolvedConfig {
  std::string entity_id;
  std::string acs_url;
  OwnedKey private_key;
  std::string private_key_pem;
  OwnedCert certificate;
  std::string certificate_pem;
  std::string idp_metadata;
  std::string request_binding = "redirect";
  std::string response_binding = "post";
  std::int64_t clock_skew_ms = 60000;
  bool want_assertions_signed = true;
  bool want_assertions_encrypted = false;
  bool allow_unsolicited = false;
  bool signals_present = false;
  bool signals_value = true;
  std::string idp_ca;
  std::string idp_entity_id;
  std::string name_id_format;
};

struct IdpInfo {
  std::string entity_id;
  std::string sso_redirect;
  std::string sso_post;
  std::map<int, std::string> artifact;
  std::string first_ars;
  std::vector<OwnedCert> certs;
  bool want_authn_requests_signed = false;
  std::vector<X509*> cert_ptrs() const;
};

ResolvedConfig resolve_config(const Json& config, const std::string& base_dir);
ResolvedConfig read_config_file(const std::string& path, const std::map<std::string, std::string>& overrides);
IdpInfo read_idp_metadata(const std::string& xml, const std::string& entity_id);
std::string write_sp_metadata(const std::string& entity_id, const std::string& acs_url, X509* cert, bool want_signed, const std::string& name_id_format);
std::string new_id();
std::string iso_now();
std::string iso_at(std::chrono::system_clock::time_point when);
std::int64_t unix_ms(std::chrono::system_clock::time_point when);

class ReplayCache {
 public:
  explicit ReplayCache(int max_entries = 10000);
  void check_and_record(const std::string& assertion_id, std::int64_t expires_ms);

 private:
  std::mutex mu_;
  std::map<std::string, std::int64_t> entries_;
  int max_;
};

struct Received {
  std::string xml;
  xmlNodePtr response = nullptr;
  std::string binding;
  std::optional<std::string> relay_state;
  bool authenticated_by_binding = false;
};

SamlLogin validate_response(const Received& received, ResolvedConfig& cfg, const IdpInfo& idp, ReplayCache& replay,
                            const std::vector<std::string>& request_ids);

std::string decrypt_element(xmlNodePtr encrypted, EVP_PKEY* key);

struct RedirectMessage {
  std::string xml;
  std::optional<std::string> relay_state;
  bool signed_ok = false;
};

std::string redirect_query(const std::string& param, const std::string& xml, const std::optional<std::string>& relay, EVP_PKEY* key);
RedirectMessage read_redirect(const std::string& raw_query, const std::string& param, const std::vector<X509*>& certs);
std::string read_post(const std::string& value, const std::string& param);
std::string post_form_html(const std::string& action, const std::vector<std::pair<std::string, std::string>>& fields, const std::string& nonce,
                           const std::string& title);
std::map<std::string, std::string> query_map(const std::string& raw);

struct ArtifactParsed {
  int endpoint_index = 0;
  std::string source_id;
};

std::string resolve_artifact(const std::string& artifact, const ResolvedConfig& cfg, const IdpInfo& idp, xmlNodePtr& response_out, std::string& xml_out);

struct ArtifactResolveView {
  std::string id;
  std::string artifact;
  bool signature_ok = false;
};
ArtifactResolveView read_artifact_resolve(const std::string& xml, const std::string& cert_pem);

struct SessionRecord {
  std::string local_id;
  std::string person;
  std::string email;
  std::string idp_session;
  std::optional<std::chrono::system_clock::time_point> expires;
};

class SessionIndex {
 public:
  explicit SessionIndex(int max_entries = 100000);
  void add(SessionRecord record);
  void remove(const std::string& local_id);
  std::vector<std::string> by_person(const std::string& person) const;
  std::vector<std::string> by_email(const std::string& email) const;
  std::vector<std::string> by_idp_session(const std::string& idp_session) const;

 private:
  std::vector<std::string> find(const std::function<bool(const SessionRecord&)>& match) const;
  void drop_locked(const std::string& local_id);
  mutable std::mutex mu_;
  mutable std::map<std::string, SessionRecord> sessions_;
  mutable std::vector<std::string> order_;
  int max_;
};

SessionRecord tracked_from(const std::string& local_id, const SamlLogin& login, const std::string& subject_attribute,
                           std::optional<std::chrono::system_clock::time_point> expires);

std::map<std::string, std::string> subject_of(const Json& sub_id, const std::string& issuer);
std::string verify_compact_jws(const std::string& token, const std::vector<Json>& keys, Json& header_out, Json& payload_out);

const std::vector<std::pair<const char*, const char*>>& event_table();
std::vector<std::string> events_with_prefix(const char* prefix);
std::vector<std::string> default_events_requested();
std::vector<std::string> default_ending_events();

struct SpImpl {
  ResolvedConfig config;
  IdpInfo idp;
  ReplayCache replay;
  bool loaded = false;
  void refresh();
  const IdpInfo& require_idp() const;
};

struct Flight {
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  bool result = false;
  std::exception_ptr err;
};

struct ReceiverImpl {
  std::string transmitter;
  std::function<void(const std::vector<std::string>&, SignalEvent&)> on_end;
  TlsOpt tls;
  bool has_tls = false;
  std::vector<std::string> events_requested;
  std::map<std::string, bool> end_on;
  SessionIndex index;
  std::string subject_attribute;
  std::string description;
  int poll_interval_ms = 5000;
  int max_events = 50;
  std::function<void(const std::string& level, const std::string& message)> log;

  mutable std::mutex mu;
  Json config;
  Json stream;
  std::vector<Json> keys;
  std::chrono::steady_clock::time_point keys_at{};
  std::vector<std::string> ack;
  std::map<std::string, Json> errs;
  std::map<std::string, std::vector<std::function<void(SignalEvent&)>>> handlers;

  std::mutex sched;
  std::condition_variable cv;
  bool running = false;
  int inflight = 0;
  int next_delay_ms = 5000;
  std::shared_ptr<Flight> flight;
  std::thread worker;
  bool worker_started = false;

  void start();
  void stop();
  bool poll_once();
  void cycle();
  std::string stream_id() const;
};

std::string lower_copy(std::string value);
std::string trim_copy(const std::string& value);
bool starts_with(const std::string& value, const std::string& prefix);
bool ends_with(const std::string& value, const std::string& suffix);
std::string join_strings(const std::vector<std::string>& parts, const std::string& sep);

}  // namespace iya::saml
