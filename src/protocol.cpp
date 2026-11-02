// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace iya::saml {
namespace {

namespace fs = std::filesystem;

std::string or_none(const std::string& value) { return value.empty() ? "(none)" : value; }

std::string read_file(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return "";
  std::ostringstream buffer;
  buffer << in.rdbuf();
  if (!in && !in.eof()) return "";
  return buffer.str();
}

bool file_ok(const fs::path& path) {
  std::error_code ec;
  return fs::is_regular_file(path, ec);
}

std::string expand_value(std::string value) {
  int seen = 0;
  while (starts_with(value, "env:") || starts_with(value, "file:")) {
    if (++seen > 4) throw Failure("config", "the placeholder " + value + " is nested too deeply");
    if (starts_with(value, "env:")) {
      std::string name = value.substr(4);
      const char* got = name.empty() ? nullptr : std::getenv(name.c_str());
      if (name.empty() || got == nullptr) throw Failure("config", "environment variable " + (name.empty() ? value : name) + " is not set");
      value = got;
      continue;
    }
    value = value.substr(5);
  }
  return value;
}

bool looks_like_pem(const std::string& value) { return value.find("-----BEGIN ") != std::string::npos; }

std::string material(const std::string& raw, const fs::path& base, const std::string& what) {
  std::string value = expand_value(raw);
  if (looks_like_pem(value)) return value;
  fs::path path(value);
  if (path.is_relative()) path = base / path;
  path = path.lexically_normal();
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Failure("config", what + " is neither a PEM nor a readable file (" + path.string() + ")");
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

bool absolute_http(const std::string& value) { return starts_with(value, "https://") || starts_with(value, "http://"); }

std::string require_absolute(const Json* value, const std::string& what) {
  if (!value || value->type != Json::Type::String || trim_copy(value->text).empty()) throw Failure("config", what + " is required");
  if (!absolute_http(value->text)) throw Failure("config", what + " must be an absolute http(s) URL, not " + value->text);
  return value->text;
}

std::string one_of(const Json* value, const std::vector<std::string>& allowed, const std::string& fallback, const std::string& what) {
  if (!value || value->type == Json::Type::Null || (value->type == Json::Type::String && value->text.empty())) return fallback;
  if (!value || value->type != Json::Type::String) {
    std::string shown = value && value->type == Json::Type::String ? value->text : json_dump(*value);
    throw Failure("config", what + " must be one of " + join_strings(allowed, ", ") + ", not " + shown);
  }
  for (const auto& item : allowed) {
    if (value->text == item) return value->text;
  }
  throw Failure("config", what + " must be one of " + join_strings(allowed, ", ") + ", not " + value->text);
}

bool bool_or(const Json& value, bool fallback) {
  if (value.type != Json::Type::Bool) return fallback;
  return value.b;
}

std::string uri_escape(const std::string& value) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : value) {
    if (std::isalnum(c) || std::string("-_.!~*'()").find(static_cast<char>(c)) != std::string::npos) out.push_back(static_cast<char>(c));
    else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 15]);
    }
  }
  return out;
}

bool is_hex(char c) { return std::isxdigit(static_cast<unsigned char>(c)); }

bool bad_percent(const std::string& value) {
  for (size_t i = 0; i < value.size(); i++) {
    if (value[i] != '%') continue;
    if (i + 2 >= value.size() || !is_hex(value[i + 1]) || !is_hex(value[i + 2])) return true;
    i += 2;
  }
  return false;
}

std::string percent_decode(const std::string& value) {
  std::string out;
  for (size_t i = 0; i < value.size(); i++) {
    if (value[i] == '%' && i + 2 < value.size() && is_hex(value[i + 1]) && is_hex(value[i + 2])) {
      auto nyb = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
      };
      out.push_back(static_cast<char>((nyb(value[i + 1]) << 4) | nyb(value[i + 2])));
      i += 2;
    } else {
      out.push_back(value[i]);
    }
  }
  return out;
}

std::string uri_unescape(const std::string& value) {
  std::string text = value;
  for (char& c : text) {
    if (c == '+') c = ' ';
  }
  std::string encoded;
  for (size_t i = 0; i < value.size(); i++) {
    if (value[i] == '+') encoded += "%20";
    else encoded.push_back(value[i]);
  }
  if (bad_percent(encoded)) throw Failure("binding", "the query string is not validly percent-encoded");
  return percent_decode(encoded);
}

std::string query_unescape(const std::string& value) {
  std::string plus = value;
  for (char& c : plus) {
    if (c == '+') c = ' ';
  }
  std::string encoded;
  for (char c : value) {
    if (c == '+') encoded += "%20";
    else encoded.push_back(c);
  }
  if (bad_percent(encoded)) return plus;
  return percent_decode(encoded);
}

xmlNodePtr document_root(xmlNodePtr el) {
  while (el && el->parent && el->parent->type == XML_ELEMENT_NODE) el = el->parent;
  return el;
}

std::optional<std::chrono::system_clock::time_point> parse_instant(const std::string& value, const std::string& what) {
  if (value.empty()) return std::nullopt;
  auto bad = [&](const std::string& prefix) { throw Failure("validation", prefix + value); };
  if (value.size() < 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' || value.back() != 'Z') {
    bad(what + " is not a UTC dateTime: ");
  }
  for (int i : {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18}) {
    if (!std::isdigit(static_cast<unsigned char>(value[static_cast<size_t>(i)]))) bad(what + " is not a UTC dateTime: ");
  }
  size_t frac_at = std::string::npos;
  if (value.size() > 20) {
    if (value[19] != '.') bad(what + " is not a UTC dateTime: ");
    frac_at = 20;
    if (frac_at + 1 >= value.size()) bad(what + " is not a UTC dateTime: ");
    for (size_t i = frac_at; i + 1 < value.size(); i++) {
      if (!std::isdigit(static_cast<unsigned char>(value[i]))) bad(what + " is not a UTC dateTime: ");
    }
  }
  std::tm tm {};
  tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
  tm.tm_mon = std::stoi(value.substr(5, 2)) - 1;
  tm.tm_mday = std::stoi(value.substr(8, 2));
  tm.tm_hour = std::stoi(value.substr(11, 2));
  tm.tm_min = std::stoi(value.substr(14, 2));
  tm.tm_sec = std::stoi(value.substr(17, 2));
  int millis = 0;
  if (frac_at != std::string::npos) {
    std::string digits = value.substr(frac_at, value.size() - frac_at - 1);
    if (digits.size() > 3) digits.resize(3);
    while (digits.size() < 3) digits.push_back('0');
    millis = std::stoi(digits);
  }
  time_t sec = timegm(&tm);
  if (sec == static_cast<time_t>(-1) && tm.tm_year < 70) bad(what + " is not a dateTime: ");
  return std::chrono::system_clock::from_time_t(sec) + std::chrono::milliseconds(millis);
}

void issuer_of(xmlNodePtr el, bool required, const std::string& expected, const std::string& what) {
  xmlNodePtr issuer = one_child(el, kNsSaml, "Issuer");
  if (!issuer) {
    if (required) throw Failure("validation", what + " has no Issuer");
    return;
  }
  std::string form = attr_of(issuer, "Format");
  if (!form.empty() && form != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") throw Failure("validation", what + "'s Issuer has the Format " + form);
  if (text_of(issuer) != expected) throw Failure("validation", what + " was issued by " + text_of(issuer) + ", not by " + expected);
}

struct Status {
  std::string code;
  std::string sub;
  std::string message;
};

Status status_of(xmlNodePtr response) {
  xmlNodePtr status = one_child(response, kNsSamlp, "Status");
  if (!status) throw Failure("validation", "the Response has no Status");
  xmlNodePtr top = one_child(status, kNsSamlp, "StatusCode");
  if (!top) throw Failure("validation", "the Response has no StatusCode");
  Status out;
  out.code = attr_of(top, "Value");
  xmlNodePtr sub = one_child(top, kNsSamlp, "StatusCode");
  if (sub && !attr_of(sub, "Value").empty()) out.sub = attr_of(sub, "Value");
  xmlNodePtr message = one_child(status, kNsSamlp, "StatusMessage");
  if (!text_of(message).empty()) out.message = text_of(message);
  return out;
}

const EVP_MD* oaep_md(const std::string& name) {
  if (name == "sha1") return EVP_sha1();
  if (name == "sha384") return EVP_sha384();
  if (name == "sha512") return EVP_sha512();
  return EVP_sha256();
}

std::string unwrap_key(xmlNodePtr encrypted_key, EVP_PKEY* key) {
  xmlNodePtr method = one_child(encrypted_key, kNsXenc, "EncryptionMethod");
  std::string alg = method ? attr_of(method, "Algorithm") : "";
  if (alg != "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" && alg != "http://www.w3.org/2009/xmlenc11#rsa-oaep") {
    throw Failure("decryption", "the content key is wrapped with " + or_none(alg) + "; only RSA-OAEP is accepted");
  }
  std::string digest = "sha1";
  if (method) {
    xmlNodePtr digest_method = one_child(method, kNsDsig, "DigestMethod");
    if (digest_method) {
      std::string digest_alg = attr_of(digest_method, "Algorithm");
      if (digest_alg == "http://www.w3.org/2000/09/xmldsig#sha1") digest = "sha1";
      else if (digest_alg == kDigest256) digest = "sha256";
      else if (digest_alg == kDigest384) digest = "sha384";
      else if (digest_alg == kDigest512) digest = "sha512";
      else throw Failure("decryption", "the OAEP digest " + digest_alg + " is not supported");
    }
  }
  std::string mgf = "sha1";
  if (alg == "http://www.w3.org/2009/xmlenc11#rsa-oaep" && method) {
    xmlNodePtr mgf_el = one_child(method, kNsXenc11, "MGF");
    if (mgf_el && !attr_of(mgf_el, "Algorithm").empty()) {
      std::string mgf_alg = attr_of(mgf_el, "Algorithm");
      if (mgf_alg == "http://www.w3.org/2009/xmlenc11#mgf1sha1") mgf = "sha1";
      else if (mgf_alg == "http://www.w3.org/2009/xmlenc11#mgf1sha256") mgf = "sha256";
      else if (mgf_alg == "http://www.w3.org/2009/xmlenc11#mgf1sha384") mgf = "sha384";
      else if (mgf_alg == "http://www.w3.org/2009/xmlenc11#mgf1sha512") mgf = "sha512";
      else throw Failure("decryption", "the OAEP mask generation function " + mgf_alg + " is not supported");
    }
  }
  if (mgf != digest) throw Failure("decryption", "OAEP with digest " + digest + " and MGF1 " + mgf + " is not supported; one hash is used for both");
  auto values = descendant_elements(encrypted_key, kNsXenc, "CipherValue");
  std::string raw = values.empty() ? "" : text_of(values[0]);
  std::string blob;
  try {
    blob = b64_decode(raw);
  } catch (...) {
    throw Failure("decryption", "the content key could not be unwrapped with this service provider's key");
  }
  return rsa_oaep_decrypt(key, blob, oaep_md(digest));
}

struct CipherSpec {
  const char* name;
  bool gcm;
  int key_len;
};

CipherSpec cipher_of(const std::string& alg) {
  if (alg == "http://www.w3.org/2009/xmlenc11#aes128-gcm") return {"aes-128-gcm", true, 16};
  if (alg == "http://www.w3.org/2009/xmlenc11#aes192-gcm") return {"aes-192-gcm", true, 24};
  if (alg == "http://www.w3.org/2009/xmlenc11#aes256-gcm") return {"aes-256-gcm", true, 32};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes128-cbc") return {"aes-128-cbc", false, 16};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes192-cbc") return {"aes-192-cbc", false, 24};
  if (alg == "http://www.w3.org/2001/04/xmlenc#aes256-cbc") return {"aes-256-cbc", false, 32};
  throw Failure("decryption", "the content is encrypted with " + or_none(alg) + ", which is not supported");
}

std::vector<X509*> certs_of(const IdpInfo& idp) { return idp.cert_ptrs(); }

std::string b64_fields(const std::string& value) {
  std::string compact;
  for (char c : value) {
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  }
  return compact;
}

}  // namespace

std::vector<X509*> IdpInfo::cert_ptrs() const {
  std::vector<X509*> out;
  for (const auto& cert : certs) out.push_back(cert.cert);
  return out;
}

std::string iso_at(std::chrono::system_clock::time_point when) {
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch());
  time_t sec = static_cast<time_t>(ms.count() / 1000);
  int millis = static_cast<int>(ms.count() % 1000);
  if (millis < 0) {
    millis += 1000;
    sec -= 1;
  }
  std::tm tm {};
  gmtime_r(&sec, &tm);
  char buf[40];
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
  return buf;
}

std::string iso_now() { return iso_at(std::chrono::system_clock::now()); }

std::int64_t unix_ms(std::chrono::system_clock::time_point when) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();
}

std::string new_id() {
  unsigned char buf[20];
  RAND_bytes(buf, sizeof buf);
  static const char* hex = "0123456789abcdef";
  std::string out = "_";
  for (unsigned char b : buf) {
    out.push_back(hex[b >> 4]);
    out.push_back(hex[b & 15]);
  }
  return out;
}

ResolvedConfig resolve_config(const Json& config, const std::string& base_dir) {
  if (config.type != Json::Type::Object) throw Failure("config", "the configuration must be an object");
  fs::path base = base_dir.empty() ? fs::current_path() : fs::path(base_dir);
  const Json* entity = config.find("entityId");
  if (!entity || entity->type != Json::Type::String || trim_copy(entity->text).empty()) throw Failure("config", "entityId is required");
  std::string acs = require_absolute(config.find("acsUrl"), "acsUrl");
  const Json* key_text = config.find("privateKey");
  const Json* cert_text = config.find("certificate");
  if (!key_text || key_text->type != Json::Type::String || !cert_text || cert_text->type != Json::Type::String) {
    throw Failure("config", "privateKey and certificate are required: every AuthnRequest is signed");
  }
  std::string key_pem = material(key_text->text, base, "privateKey");
  std::string cert_pem = material(cert_text->text, base, "certificate");
  OwnedKey signer = load_private_key(key_pem);
  OwnedCert certificate = load_certificate(cert_pem);
  std::string kind = rsa_kind(signer.key);
  if (!kind.empty()) throw Failure("config", "the private key is " + kind + "; an RSA key is required");
  if (!same_rsa_public(signer.key, certificate.cert)) throw Failure("config", "the certificate is not for the private key");
  const Json* idp_meta = config.find("idpMetadata");
  if (!idp_meta || idp_meta->type != Json::Type::String || trim_copy(idp_meta->text).empty()) throw Failure("config", "idpMetadata is required");
  std::string idp = expand_value(trim_copy(idp_meta->text));
  if (!absolute_http(idp) && !starts_with(idp, "<")) {
    fs::path path(idp);
    if (path.is_relative()) path = base / path;
    idp = path.lexically_normal().string();
  }
  double skew = 60;
  if (const Json* raw = config.find("clockSkewSeconds"); raw && raw->type != Json::Type::Null) {
    if (raw->type != Json::Type::Number || raw->num < 0 || raw->num > 600) throw Failure("config", "clockSkewSeconds must be a number from 0 to 600");
    skew = raw->num;
  }
  if (const Json* raw = config.find("signals")) {
    if (raw->type != Json::Type::Bool) throw Failure("config", "signals must be true or false");
  }
  ResolvedConfig out;
  out.entity_id = entity->text;
  out.acs_url = acs;
  out.private_key_pem = private_key_to_pem(signer.key);
  out.certificate_pem = certificate_to_pem(certificate.cert);
  out.private_key = std::move(signer);
  out.certificate = std::move(certificate);
  out.idp_metadata = idp;
  out.clock_skew_ms = static_cast<std::int64_t>(static_cast<int>(skew)) * 1000;
  if (const Json* raw = config.find("wantAssertionsSigned"); raw && raw->type != Json::Type::Null) out.want_assertions_signed = bool_or(*raw, true);
  if (const Json* raw = config.find("wantAssertionsEncrypted"); raw && raw->type != Json::Type::Null) out.want_assertions_encrypted = bool_or(*raw, false);
  if (const Json* raw = config.find("allowUnsolicited"); raw && raw->type != Json::Type::Null) out.allow_unsolicited = bool_or(*raw, false);
  out.request_binding = one_of(config.find("requestBinding"), {"redirect", "post"}, "redirect", "requestBinding");
  out.response_binding = one_of(config.find("responseBinding"), {"post", "redirect", "artifact"}, "post", "responseBinding");
  if (const Json* raw = config.find("signals"); raw && raw->type == Json::Type::Bool && !raw->b) {
    out.signals_present = true;
    out.signals_value = false;
  }
  if (const Json* raw = config.find("idpCa"); raw && raw->type == Json::Type::String && !raw->text.empty()) out.idp_ca = material(raw->text, base, "idpCa");
  if (const Json* raw = config.find("idpEntityId"); raw && raw->type == Json::Type::String && !raw->text.empty()) out.idp_entity_id = raw->text;
  if (const Json* raw = config.find("nameIdFormat"); raw && raw->type == Json::Type::String && !raw->text.empty()) out.name_id_format = raw->text;
  return out;
}

ResolvedConfig read_config_file(const std::string& path, const std::map<std::string, std::string>& overrides) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Failure("config", path + " cannot be read as JSON: cannot open");
  std::ostringstream buffer;
  buffer << in.rdbuf();
  Json parsed;
  try {
    parsed = parse_json(buffer.str());
  } catch (const Failure& failure) {
    throw Failure("config", path + " cannot be read as JSON: " + failure.what());
  }
  if (parsed.type != Json::Type::Object) throw Failure("config", "the configuration must be an object");
  for (const auto& item : overrides) {
    Json value;
    value.type = Json::Type::String;
    value.text = item.second;
    bool found = false;
    for (auto& field : parsed.fields) {
      if (field.first == item.first) {
        field.second = value;
        found = true;
        break;
      }
    }
    if (!found) parsed.fields.emplace_back(item.first, value);
  }
  fs::path abs = fs::absolute(path);
  return resolve_config(parsed, abs.parent_path().string());
}

IdpInfo read_idp_metadata(const std::string& xml, const std::string& wanted) {
  XmlDoc doc = parse_xml(xml, "the identity provider metadata");
  xmlNodePtr root = doc.root();
  xmlNodePtr entity = nullptr;
  if (same_element(root, kNsMd, "EntityDescriptor")) entity = root;
  else if (same_element(root, kNsMd, "EntitiesDescriptor")) {
    std::vector<xmlNodePtr> all;
    for (xmlNodePtr item : descendant_elements(root, kNsMd, "EntityDescriptor")) {
      if (!descendant_elements(item, kNsMd, "IDPSSODescriptor").empty()) all.push_back(item);
    }
    if (!wanted.empty()) {
      for (xmlNodePtr item : all) {
        if (attr_of(item, "entityID") == wanted) {
          entity = item;
          break;
        }
      }
    } else if (all.size() == 1) entity = all[0];
    if (!entity) {
      if (!wanted.empty()) throw Failure("metadata", "the metadata aggregate has no identity provider " + wanted);
      throw Failure("metadata", "the metadata aggregate holds " + std::to_string(all.size()) + " identity providers; name one with idpEntityId");
    }
  } else {
    throw Failure("metadata", "the identity provider metadata is not an EntityDescriptor");
  }
  std::string identifier = attr_of(entity, "entityID");
  if (identifier.empty()) throw Failure("metadata", "the identity provider metadata has no entityID");
  if (!wanted.empty() && identifier != wanted) throw Failure("metadata", "the metadata describes " + identifier + ", not " + wanted);
  auto roles = child_elements(entity, kNsMd, "IDPSSODescriptor");
  if (roles.empty()) throw Failure("metadata", identifier + "'s metadata has no IDPSSODescriptor");
  xmlNodePtr role = roles[0];
  IdpInfo info;
  info.entity_id = identifier;
  for (xmlNodePtr item : child_elements(role, kNsMd, "SingleSignOnService")) {
    std::string location = attr_of(item, "Location");
    if (location.empty()) continue;
    std::string binding = attr_of(item, "Binding");
    if (binding == kBindingRedirect && info.sso_redirect.empty()) info.sso_redirect = location;
    if (binding == kBindingPost && info.sso_post.empty()) info.sso_post = location;
  }
  for (xmlNodePtr ars : child_elements(role, kNsMd, "ArtifactResolutionService")) {
    std::string location = attr_of(ars, "Location");
    if (attr_of(ars, "Binding") == kBindingSoap && !location.empty()) {
      int index = std::atoi(attr_of(ars, "index").c_str());
      if (!info.artifact.count(index)) {
        info.artifact[index] = location;
        if (info.first_ars.empty()) info.first_ars = location;
      }
    }
  }
  for (xmlNodePtr descriptor : child_elements(role, kNsMd, "KeyDescriptor")) {
    std::string use = attr_of(descriptor, "use");
    if (!use.empty() && use != "signing") continue;
    for (xmlNodePtr data : descendant_elements(descriptor, kNsDsig, "X509Data")) {
      auto first = child_elements(data, kNsDsig, "X509Certificate");
      if (first.empty()) continue;
      try {
        info.certs.push_back(load_certificate(to_pem_cert(text_of(first[0]))));
      } catch (...) {
        throw Failure("metadata", "a signing certificate in the identity provider's metadata cannot be read");
      }
    }
  }
  if (info.certs.empty()) throw Failure("metadata", identifier + "'s metadata names no signing certificate");
  if (info.sso_redirect.empty() && info.sso_post.empty()) throw Failure("metadata", identifier + "'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService");
  info.want_authn_requests_signed = attr_of(role, "WantAuthnRequestsSigned") == "true";
  return info;
}

std::string write_sp_metadata(const std::string& entity_id, const std::string& acs_url, X509* cert, bool want_signed, const std::string& name_id_format) {
  static const char* methods[] = {"http://www.w3.org/2009/xmlenc11#aes256-gcm", "http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                                  "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"};
  std::string key_info = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + pem_body(certificate_to_pem(cert)) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
  std::string method_xml;
  for (const char* method : methods) method_xml += std::string("\n      <md:EncryptionMethod Algorithm=\"") + method + "\"/>";
  auto key = [&](const std::string& use) {
    std::string extra = use == "encryption" ? method_xml : "";
    return "    <md:KeyDescriptor use=\"" + use + "\">\n      " + key_info + extra + "\n    </md:KeyDescriptor>";
  };
  std::string name_id;
  if (!name_id_format.empty()) name_id = "\n    <md:NameIDFormat>" + escape_xml(name_id_format) + "</md:NameIDFormat>";
  std::string want = want_signed ? "true" : "false";
  std::string acs = escape_xml(acs_url);
  return std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n") + "<md:EntityDescriptor xmlns:md=\"" + kNsMd + "\" xmlns:ds=\"" + kNsDsig + "\" entityID=\"" + escape_xml(entity_id) +
         "\">\n  <md:SPSSODescriptor protocolSupportEnumeration=\"" + kNsSamlp + "\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"" + want + "\">\n" + key("signing") + "\n" +
         key("encryption") + name_id + "\n    <md:AssertionConsumerService Binding=\"" + kBindingPost + "\" Location=\"" + acs +
         "\" index=\"0\" isDefault=\"true\"/>\n    <md:AssertionConsumerService Binding=\"" + kBindingRedirect + "\" Location=\"" + acs +
         "\" index=\"1\"/>\n    <md:AssertionConsumerService Binding=\"" + kBindingArtifact + "\" Location=\"" + acs + "\" index=\"2\"/>\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n";
}

ReplayCache::ReplayCache(int max_entries) : max_(max_entries > 0 ? max_entries : 10000) {}

void ReplayCache::check_and_record(const std::string& assertion_id, std::int64_t expires_ms) {
  std::int64_t now = unix_ms(std::chrono::system_clock::now());
  std::lock_guard<std::mutex> lock(mu_);
  auto found = entries_.find(assertion_id);
  if (found != entries_.end() && found->second > now) throw Failure("replay", "the assertion " + assertion_id.substr(assertion_id.find(' ') + 1) + " has been accepted before");
  if (static_cast<int>(entries_.size()) >= max_) {
    for (auto it = entries_.begin(); it != entries_.end();) {
      if (it->second <= now) it = entries_.erase(it);
      else ++it;
    }
    if (static_cast<int>(entries_.size()) >= max_) throw Failure("replay", "the replay cache holds " + std::to_string(max_) + " live assertions and cannot record another");
  }
  entries_[assertion_id] = expires_ms;
}

std::string node_local(xmlNodePtr node) {
  if (!node || !node->name) return "";
  return reinterpret_cast<const char*>(node->name);
}

std::string decrypt_element(xmlNodePtr encrypted, EVP_PKEY* key) {
  xmlNodePtr data = one_child(encrypted, kNsXenc, "EncryptedData");
  if (!data) throw Failure("decryption", "<" + node_local(encrypted) + "> has no EncryptedData");
  xmlNodePtr method = one_child(data, kNsXenc, "EncryptionMethod");
  std::string alg = method ? attr_of(method, "Algorithm") : "";
  CipherSpec spec = cipher_of(alg);
  auto keys = descendant_elements(encrypted, kNsXenc, "EncryptedKey");
  if (keys.empty()) throw Failure("decryption", "<" + node_local(encrypted) + "> carries no EncryptedKey");
  std::string content_key = unwrap_key(keys[0], key);
  if (static_cast<int>(content_key.size()) != spec.key_len) {
    throw Failure("decryption", "the content key is " + std::to_string(content_key.size()) + " bytes; " + spec.name + " needs " + std::to_string(spec.key_len));
  }
  xmlNodePtr cipher_data = one_child(data, kNsXenc, "CipherData");
  xmlNodePtr cipher_value = cipher_data ? one_child(cipher_data, kNsXenc, "CipherValue") : nullptr;
  std::string blob;
  try {
    blob = b64_decode(text_of(cipher_value));
  } catch (...) {
    throw Failure("decryption", "the content could not be decrypted");
  }
  if (spec.gcm) return aes_gcm_decrypt(content_key, blob);
  return aes_cbc_decrypt(content_key, blob);
}

}  // namespace iya::saml
