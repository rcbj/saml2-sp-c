// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <openssl/rand.h>

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace iya::saml {
namespace {

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
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
      };
      out.push_back(static_cast<char>((nyb(value[i + 1]) << 4) | nyb(value[i + 2])));
      i += 2;
    } else out.push_back(value[i]);
  }
  return out;
}

std::string uri_unescape(const std::string& value) {
  std::string encoded;
  for (char c : value) {
    if (c == '+') encoded += "%20";
    else encoded.push_back(c);
  }
  if (bad_percent(encoded)) throw Failure("binding", "the query string is not validly percent-encoded");
  return percent_decode(encoded);
}

std::string query_unescape(const std::string& value) {
  std::string encoded;
  for (char c : value) {
    if (c == '+') encoded += "%20";
    else encoded.push_back(c);
  }
  if (bad_percent(encoded)) {
    std::string plus = value;
    for (char& c : plus)
      if (c == '+') c = ' ';
    return plus;
  }
  return percent_decode(encoded);
}

xmlNodePtr document_root(xmlNodePtr el) {
  while (el && el->parent && el->parent->type == XML_ELEMENT_NODE) el = el->parent;
  return el;
}

std::optional<std::chrono::system_clock::time_point> parse_instant(const std::string& value, const std::string& what) {
  if (value.empty()) return std::nullopt;
  auto bad = [&](const char* prefix) { throw Failure("validation", std::string(prefix) + value); };
  if (value.size() < 20 || value.back() != 'Z') bad(what.c_str()[0] ? "" : "");
  bool shape = value.size() >= 20 && value[4] == '-' && value[7] == '-' && value[10] == 'T' && value[13] == ':' && value[16] == ':' && value.back() == 'Z';
  if (!shape) throw Failure("validation", what + " is not a UTC dateTime: " + value);
  for (int i : {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18}) {
    if (!std::isdigit(static_cast<unsigned char>(value[static_cast<size_t>(i)]))) throw Failure("validation", what + " is not a UTC dateTime: " + value);
  }
  size_t frac = std::string::npos;
  if (value.size() != 20) {
    if (value[19] != '.') throw Failure("validation", what + " is not a UTC dateTime: " + value);
    for (size_t i = 20; i + 1 < value.size(); i++) {
      if (!std::isdigit(static_cast<unsigned char>(value[i]))) throw Failure("validation", what + " is not a UTC dateTime: " + value);
    }
    if (value.size() < 22) throw Failure("validation", what + " is not a UTC dateTime: " + value);
    frac = 20;
  }
  std::tm tm {};
  tm.tm_year = std::stoi(value.substr(0, 4)) - 1900;
  tm.tm_mon = std::stoi(value.substr(5, 2)) - 1;
  tm.tm_mday = std::stoi(value.substr(8, 2));
  tm.tm_hour = std::stoi(value.substr(11, 2));
  tm.tm_min = std::stoi(value.substr(14, 2));
  tm.tm_sec = std::stoi(value.substr(17, 2));
  int millis = 0;
  if (frac != std::string::npos) {
    std::string digits = value.substr(frac, value.size() - frac - 1);
    if (digits.size() > 3) digits.resize(3);
    while (digits.size() < 3) digits.push_back('0');
    millis = std::stoi(digits);
  }
  time_t sec = timegm(&tm);
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

struct StatusBits {
  std::string code;
  std::string sub;
  std::string message;
};

StatusBits status_of(xmlNodePtr response) {
  xmlNodePtr status = one_child(response, kNsSamlp, "Status");
  if (!status) throw Failure("validation", "the Response has no Status");
  xmlNodePtr top = one_child(status, kNsSamlp, "StatusCode");
  if (!top) throw Failure("validation", "the Response has no StatusCode");
  StatusBits out;
  out.code = attr_of(top, "Value");
  if (xmlNodePtr sub = one_child(top, kNsSamlp, "StatusCode"); sub && !attr_of(sub, "Value").empty()) out.sub = attr_of(sub, "Value");
  if (xmlNodePtr message = one_child(status, kNsSamlp, "StatusMessage"); !text_of(message).empty()) out.message = text_of(message);
  return out;
}

std::string raw_query_of(const std::string& raw_url) {
  auto q = raw_url.find('?');
  if (q == std::string::npos) return "";
  std::string query = raw_url.substr(q + 1);
  auto hash = query.find('#');
  if (hash != std::string::npos) query.resize(hash);
  return query;
}

const EVP_MD* sig_md(const std::string& alg) {
  if (alg == kRsaSha256) return EVP_sha256();
  if (alg == kRsaSha384) return EVP_sha384();
  if (alg == kRsaSha512) return EVP_sha512();
  return nullptr;
}

std::string binding_uri(const std::string& response) {
  if (response == "redirect") return kBindingRedirect;
  if (response == "artifact") return kBindingArtifact;
  return kBindingPost;
}

}  // namespace

std::string redirect_query(const std::string& param, const std::string& xml, const std::optional<std::string>& relay, EVP_PKEY* key) {
  std::string deflated;
  try {
    deflated = deflate_raw(xml);
  } catch (const Failure& failure) {
    if (failure.kind == "binding") throw;
    throw Failure("binding", "the message could not be deflated");
  }
  std::string encoded = b64_encode(deflated);
  std::vector<std::string> parts{param + "=" + uri_escape(encoded)};
  if (relay) parts.push_back("RelayState=" + uri_escape(*relay));
  parts.push_back(std::string("SigAlg=") + uri_escape(kRsaSha256));
  std::string signed_text = join_strings(parts, "&");
  std::string sig = rsa_sign_pkcs1(key, signed_text, EVP_sha256());
  return signed_text + "&Signature=" + uri_escape(b64_encode(sig));
}

RedirectMessage read_redirect(const std::string& raw_query, const std::string& param, const std::vector<X509*>& certs) {
  std::string query = raw_query;
  if (starts_with(query, "?")) query = query.substr(1);
  std::map<std::string, std::string> raw;
  size_t i = 0;
  while (i <= query.size()) {
    auto amp = query.find('&', i);
    if (amp == std::string::npos) amp = query.size();
    std::string pair = query.substr(i, amp - i);
    i = amp + 1;
    if (pair.empty()) {
      if (amp == query.size()) break;
      continue;
    }
    auto eq = pair.find('=');
    std::string name = eq == std::string::npos ? pair : pair.substr(0, eq);
    std::string value = eq == std::string::npos ? "" : pair.substr(eq + 1);
    name = uri_unescape(name);
    if (raw.count(name)) throw Failure("binding", "the query string carries " + name + " twice");
    raw[name] = value;
    if (amp == query.size()) break;
  }
  if (!raw.count(param)) throw Failure("binding", "the query string carries no " + param);
  std::string unescaped = uri_unescape(raw[param]);
  std::string decoded;
  try {
    decoded = b64_decode(unescaped);
  } catch (...) {
    throw Failure("binding", param + " is not a DEFLATE-encoded message");
  }
  std::string inflated;
  try {
    inflated = inflate_raw(decoded);
  } catch (const Failure& failure) {
    if (failure.kind == "binding") throw;
    throw Failure("binding", param + " is not a DEFLATE-encoded message");
  }
  RedirectMessage message;
  message.xml = inflated;
  if (raw.count("RelayState")) message.relay_state = uri_unescape(raw["RelayState"]);
  if (!raw.count("Signature")) return message;
  std::string sig_alg = uri_unescape(raw["SigAlg"]);
  const EVP_MD* md = sig_md(sig_alg);
  if (!md) throw Failure("signature", "the query is signed with " + (sig_alg.empty() ? "(no SigAlg)" : sig_alg) + ", which is refused");
  std::vector<std::string> parts{param + "=" + raw[param]};
  if (raw.count("RelayState")) parts.push_back("RelayState=" + raw["RelayState"]);
  parts.push_back("SigAlg=" + raw["SigAlg"]);
  std::string data = join_strings(parts, "&");
  std::string sig_text;
  try {
    sig_text = uri_unescape(raw["Signature"]);
  } catch (...) {
    throw Failure("signature", "the query string signature does not verify against the identity provider's certificate");
  }
  std::string sig_bytes;
  try {
    sig_bytes = b64_decode(sig_text);
  } catch (...) {
    throw Failure("signature", "the query string signature does not verify against the identity provider's certificate");
  }
  for (X509* cert : certs) {
    OwnedKey pub(X509_get_pubkey(cert));
    if (!pub.key) continue;
    if (rsa_verify_pkcs1(pub.key, data, sig_bytes, md)) {
      message.signed_ok = true;
      return message;
    }
  }
  throw Failure("signature", "the query string signature does not verify against the identity provider's certificate");
}

std::string read_post(const std::string& value, const std::string& param) {
  std::string compact;
  for (char c : value)
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  bool ok = !compact.empty();
  for (char c : compact) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '/' && c != '=') ok = false;
  }
  if (ok) {
    size_t eq = 0;
    while (!compact.empty() && compact.back() == '=') {
      compact.pop_back();
      eq++;
    }
    if (eq > 2) ok = false;
    compact.append(eq, '=');
  }
  if (!ok) throw Failure("binding", param + " is not base64");
  try {
    return b64_decode(compact);
  } catch (...) {
    throw Failure("binding", param + " is not base64");
  }
}

std::string post_form_html(const std::string& action, const std::vector<std::pair<std::string, std::string>>& fields, const std::string& nonce, const std::string& title_in) {
  std::string title = title_in.empty() ? "Signing in" : title_in;
  std::vector<std::string> lines;
  for (const auto& field : fields) lines.push_back("<input type=\"hidden\" name=\"" + escape_xml(field.first) + "\" value=\"" + escape_xml(field.second) + "\">");
  std::string script;
  if (!nonce.empty()) script = "\n    <script nonce=\"" + escape_xml(nonce) + "\">document.forms[0].submit();</script>";
  return "<!doctype html>\n<html lang=\"en\">\n  <head><meta charset=\"utf-8\"><title>" + escape_xml(title) + "</title></head>\n  <body>\n    <form method=\"post\" action=\"" +
         escape_xml(action) + "\">\n      " + join_strings(lines, "\n      ") +
         "\n      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>\n      <button type=\"submit\">Continue</button>\n    </form>" + script +
         "\n  </body>\n</html>\n";
}

std::map<std::string, std::string> query_map(const std::string& raw) {
  std::map<std::string, std::string> out;
  if (raw.empty()) return out;
  size_t i = 0;
  while (i <= raw.size()) {
    auto amp = raw.find('&', i);
    if (amp == std::string::npos) amp = raw.size();
    std::string part = raw.substr(i, amp - i);
    i = amp + 1;
    if (!part.empty()) {
      auto eq = part.find('=');
      std::string key = eq == std::string::npos ? part : part.substr(0, eq);
      std::string val = eq == std::string::npos ? "" : part.substr(eq + 1);
      key = query_unescape(key);
      val = query_unescape(val);
      if (!out.count(key)) out[key] = val;
    }
    if (amp == raw.size()) break;
  }
  return out;
}

SamlLogin validate_response(const Received& received, ResolvedConfig& cfg, const IdpInfo& idp, ReplayCache& replay, const std::vector<std::string>& request_ids) {
  auto now = std::chrono::system_clock::now();
  std::int64_t now_ms = unix_ms(now);
  std::int64_t skew = cfg.clock_skew_ms;
  std::vector<XmlDoc> keep;
  xmlNodePtr response = received.response;
  assert_unique_ids(document_root(response));
  if (!same_element(response, kNsSamlp, "Response")) throw Failure("validation", "the message is a <" + std::string(reinterpret_cast<const char*>(response->name)) + ">, not a Response");
  std::string signed_form = verify_signed(response, idp.cert_ptrs(), "the Response");
  if (!signed_form.empty()) {
    keep.push_back(parse_xml(signed_form, "the signed Response"));
    response = keep.back().root();
  }
  bool response_authenticated = !signed_form.empty() || received.authenticated_by_binding;
  std::string version = attr_of(response, "Version");
  if (version != "2.0") throw Failure("validation", "the Response is version " + (version.empty() ? "(none)" : version) + ", not 2.0");
  if (!has_attr(response, "ID") || attr_of(response, "ID").empty()) throw Failure("validation", "the Response has no ID");
  std::string response_id = attr_of(response, "ID");
  issuer_of(response, false, idp.entity_id, "the Response");
  bool has_dest = has_attr(response, "Destination");
  std::string destination = attr_of(response, "Destination");
  if (has_dest && destination != cfg.acs_url) throw Failure("validation", "the Response is addressed to " + destination + ", not to " + cfg.acs_url);
  if (!has_dest && response_authenticated && received.binding != "artifact") throw Failure("validation", "the Response is signed but has no Destination");
  std::optional<std::string> in_response_to;
  if (has_attr(response, "InResponseTo")) {
    in_response_to = attr_of(response, "InResponseTo");
    bool found = false;
    for (const auto& id : request_ids)
      if (id == *in_response_to) found = true;
    if (!found) throw Failure("validation", "the Response answers " + *in_response_to + ", which is not a request this browser has outstanding");
  } else if (!cfg.allow_unsolicited) {
    throw Failure("validation", "the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted");
  }
  StatusBits status = status_of(response);
  if (status.code != kStatusSuccess) {
    std::string detail = status.sub.empty() ? status.code : status.sub;
    std::string suffix = status.message.empty() ? "" : ": " + status.message;
    throw Failure::status_error("the identity provider answered " + detail + suffix, status.code, status.sub, status.message);
  }
  auto plain = child_elements(response, kNsSaml, "Assertion");
  auto encrypted = child_elements(response, kNsSaml, "EncryptedAssertion");
  if (plain.size() + encrypted.size() != 1) throw Failure("validation", "the Response holds " + std::to_string(plain.size() + encrypted.size()) + " assertions; exactly one is accepted");
  xmlNodePtr assertion = nullptr;
  bool was_encrypted = false;
  if (encrypted.size() == 1) {
    was_encrypted = true;
    std::string assertion_xml = decrypt_element(encrypted[0], cfg.private_key.key);
    keep.push_back(parse_xml(assertion_xml, "the decrypted assertion"));
    assert_unique_ids(keep.back().root());
    assertion = keep.back().root();
    if (!same_element(assertion, kNsSaml, "Assertion")) throw Failure("validation", "the EncryptedAssertion does not hold an Assertion");
  } else {
    if (cfg.want_assertions_encrypted) throw Failure("validation", "the assertion is not encrypted, and wantAssertionsEncrypted is on");
    assertion = plain[0];
  }
  std::string signed_assertion = verify_signed(assertion, idp.cert_ptrs(), "the assertion");
  if (!signed_assertion.empty()) {
    keep.push_back(parse_xml(signed_assertion, "the signed assertion"));
    assertion = keep.back().root();
  } else if (cfg.want_assertions_signed) {
    throw Failure("validation", "the assertion is not signed, and wantAssertionsSigned is on");
  } else if (!response_authenticated) {
    throw Failure("validation", "neither the Response nor its assertion is signed");
  }
  if (attr_of(assertion, "Version") != "2.0") throw Failure("validation", "the assertion is not version 2.0");
  if (!has_attr(assertion, "ID") || attr_of(assertion, "ID").empty()) throw Failure("validation", "the assertion has no ID");
  std::string assertion_id = attr_of(assertion, "ID");
  issuer_of(assertion, true, idp.entity_id, "the assertion");
  xmlNodePtr subject = one_child(assertion, kNsSaml, "Subject");
  if (!subject) throw Failure("validation", "the assertion has no Subject");
  xmlNodePtr name_id = one_child(subject, kNsSaml, "NameID");
  xmlNodePtr encrypted_id = one_child(subject, kNsSaml, "EncryptedID");
  if (!name_id && encrypted_id) {
    std::string xml = decrypt_element(encrypted_id, cfg.private_key.key);
    keep.push_back(parse_xml(xml, "the decrypted NameID"));
    name_id = keep.back().root();
    if (!same_element(name_id, kNsSaml, "NameID")) throw Failure("validation", "the EncryptedID does not hold a NameID");
  }
  if (!name_id || text_of(name_id).empty()) throw Failure("validation", "the assertion's Subject has no NameID");
  std::vector<std::string> reasons;
  std::optional<std::chrono::system_clock::time_point> confirmed_until;
  for (xmlNodePtr confirmation : child_elements(subject, kNsSaml, "SubjectConfirmation")) {
    if (attr_of(confirmation, "Method") != kBearer) {
      reasons.push_back("method " + attr_of(confirmation, "Method"));
      continue;
    }
    xmlNodePtr data = one_child(confirmation, kNsSaml, "SubjectConfirmationData");
    if (!data) {
      reasons.push_back("no SubjectConfirmationData");
      continue;
    }
    std::string recipient = attr_of(data, "Recipient");
    auto not_on_or_after = parse_instant(attr_of(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
    bool has_not_before = has_attr(data, "NotBefore");
    bool has_sc = has_attr(data, "InResponseTo");
    std::string sc_in = attr_of(data, "InResponseTo");
    if (recipient != cfg.acs_url) reasons.push_back("Recipient " + (recipient.empty() ? "(none)" : recipient));
    else if (!not_on_or_after) reasons.push_back("no NotOnOrAfter");
    else if (unix_ms(*not_on_or_after) <= now_ms - skew) reasons.push_back("expired at " + iso_at(*not_on_or_after));
    else if (has_not_before) reasons.push_back("a NotBefore, which a bearer confirmation must not have");
    else if ((has_sc && (!in_response_to || sc_in != *in_response_to)) || (!has_sc && in_response_to)) {
      std::string shown = (!has_sc || sc_in.empty()) ? "(none)" : sc_in;
      reasons.push_back("InResponseTo " + shown);
    } else {
      confirmed_until = not_on_or_after;
      break;
    }
  }
  if (!confirmed_until) {
    std::string why = reasons.empty() ? "there is none" : join_strings(reasons, "; ");
    throw Failure("validation", "no bearer SubjectConfirmation of the assertion fits: " + why);
  }
  xmlNodePtr conditions = one_child(assertion, kNsSaml, "Conditions");
  if (!conditions) throw Failure("validation", "the assertion has no Conditions, so it names no audience");
  auto not_before_c = parse_instant(attr_of(conditions, "NotBefore"), "Conditions NotBefore");
  auto not_on_or_after_c = parse_instant(attr_of(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter");
  if (not_before_c && unix_ms(*not_before_c) > now_ms + skew) throw Failure("validation", "the assertion is not valid before " + iso_at(*not_before_c));
  if (not_on_or_after_c && unix_ms(*not_on_or_after_c) <= now_ms - skew) throw Failure("validation", "the assertion expired at " + iso_at(*not_on_or_after_c));
  auto restrictions = child_elements(conditions, kNsSaml, "AudienceRestriction");
  if (restrictions.empty()) throw Failure("validation", "the assertion has no AudienceRestriction");
  for (xmlNodePtr restriction : restrictions) {
    bool ok_aud = false;
    for (xmlNodePtr audience : child_elements(restriction, kNsSaml, "Audience")) {
      if (text_of(audience) == cfg.entity_id) ok_aud = true;
    }
    if (!ok_aud) throw Failure("validation", "the assertion is not for " + cfg.entity_id);
  }
  auto authn_statements = child_elements(assertion, kNsSaml, "AuthnStatement");
  if (authn_statements.empty()) throw Failure("validation", "the assertion has no AuthnStatement");
  xmlNodePtr authn = authn_statements[0];
  auto authn_instant = parse_instant(attr_of(authn, "AuthnInstant"), "AuthnInstant");
  if (!authn_instant) throw Failure("validation", "the AuthnStatement has no AuthnInstant");
  auto session_not_on_or_after = parse_instant(attr_of(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter");
  if (session_not_on_or_after && unix_ms(*session_not_on_or_after) <= now_ms - skew) throw Failure("validation", "the identity provider's session has already ended");
  xmlNodePtr context = one_child(authn, kNsSaml, "AuthnContext");
  std::string class_ref;
  if (context) class_ref = text_of(one_child(context, kNsSaml, "AuthnContextClassRef"));
  SamlLogin login;
  for (xmlNodePtr statement : child_elements(assertion, kNsSaml, "AttributeStatement")) {
    std::vector<xmlNodePtr> attrs = child_elements(statement, kNsSaml, "Attribute");
    for (xmlNodePtr enc : child_elements(statement, kNsSaml, "EncryptedAttribute")) {
      std::string xml = decrypt_element(enc, cfg.private_key.key);
      keep.push_back(parse_xml(xml, "the decrypted attribute"));
      if (!same_element(keep.back().root(), kNsSaml, "Attribute")) throw Failure("validation", "an EncryptedAttribute does not hold an Attribute");
      attrs.push_back(keep.back().root());
    }
    for (xmlNodePtr attribute : attrs) {
      std::string name = attr_of(attribute, "Name");
      if (name.empty()) continue;
      for (xmlNodePtr value : child_elements(attribute, kNsSaml, "AttributeValue")) login.attributes[name].push_back(iter_text(value));
      if (std::string friendly = attr_of(attribute, "FriendlyName"); !friendly.empty()) login.attribute_friendly_names[name] = friendly;
    }
  }
  std::int64_t keep_until = unix_ms(*confirmed_until);
  if (not_on_or_after_c && unix_ms(*not_on_or_after_c) > keep_until) keep_until = unix_ms(*not_on_or_after_c);
  keep_until += skew;
  replay.check_and_record(idp.entity_id + " " + assertion_id, keep_until);
  login.name_id = text_of(name_id);
  login.name_id_format = attr_of(name_id, "Format");
  login.name_qualifier = attr_of(name_id, "NameQualifier");
  login.sp_name_qualifier = attr_of(name_id, "SPNameQualifier");
  login.session_index = attr_of(authn, "SessionIndex");
  login.session_not_on_or_after = session_not_on_or_after;
  login.authn_instant = *authn_instant;
  login.authn_context_class_ref = class_ref;
  login.issuer = idp.entity_id;
  login.in_response_to = in_response_to;
  login.relay_state = received.relay_state;
  login.binding = received.binding;
  login.encrypted = was_encrypted;
  login.response_id = response_id;
  login.assertion_id = assertion_id;
  return login;
}

namespace {

struct ArtifactResult {
  std::string xml;
  XmlDoc doc;
  xmlNodePtr response = nullptr;
};

ArtifactResult resolve_artifact_doc(const std::string& artifact, const ResolvedConfig& cfg, const IdpInfo& idp) {
  std::string compact;
  for (char c : artifact)
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  std::string raw;
  try {
    raw = b64_decode(compact);
  } catch (...) {
    raw.clear();
  }
  if (raw.size() != 44 || static_cast<unsigned char>(raw[0]) != 0 || static_cast<unsigned char>(raw[1]) != 4) {
    throw Failure("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact");
  }
  int index = (static_cast<unsigned char>(raw[2]) << 8) | static_cast<unsigned char>(raw[3]);
  std::string source = raw.substr(4, 20);
  if (source != sha1_raw(idp.entity_id)) throw Failure("artifact", "the artifact was not issued by " + idp.entity_id);
  std::string location;
  auto found = idp.artifact.find(index);
  if (found != idp.artifact.end()) location = found->second;
  else if (index == 0 && !idp.artifact.empty()) location = idp.first_ars;
  if (location.empty()) throw Failure("artifact", "the identity provider's metadata has no SOAP ArtifactResolutionService with index " + std::to_string(index));
  std::string element_id = new_id();
  std::string unsigned_xml = "<samlp:ArtifactResolve xmlns:samlp=\"" + std::string(kNsSamlp) + "\" xmlns:saml=\"" + kNsSaml + "\" ID=\"" + element_id + "\" Version=\"2.0\" IssueInstant=\"" + iso_now() +
                             "\" Destination=\"" + escape_xml(location) + "\"><saml:Issuer>" + escape_xml(cfg.entity_id) + "</saml:Issuer><samlp:Artifact>" + escape_xml(artifact) +
                             "</samlp:Artifact></samlp:ArtifactResolve>";
  std::string signed_xml = sign_enveloped(unsigned_xml, element_id, cfg.private_key.key, cfg.certificate.cert);
  std::string envelope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"" + std::string(kNsSoap) + "\"><soap:Body>" + signed_xml + "</soap:Body></soap:Envelope>";
  TlsOpt tls_store;
  const TlsOpt* tls = nullptr;
  if (!cfg.idp_ca.empty()) {
    tls_store.ca = cfg.idp_ca;
    tls = &tls_store;
  }
  HttpResult answer = http_send(location, "POST",
                                {{"content-type", "text/xml; charset=utf-8"}, {"soapaction", "\"http://www.oasis-open.org/committees/security\""}, {"accept", "text/xml"}}, envelope, tls,
                                "artifact");
  if (answer.status != 200) throw Failure("artifact", "the artifact resolution service answered HTTP " + std::to_string(answer.status));
  ArtifactResult result;
  result.doc = parse_xml(answer.body, "the ArtifactResponse");
  result.xml = answer.body;
  assert_unique_ids(result.doc.root());
  xmlNodePtr body = nullptr;
  if (same_element(result.doc.root(), kNsSoap, "Envelope")) body = one_child(result.doc.root(), kNsSoap, "Body");
  xmlNodePtr artifact_response = body ? one_child(body, kNsSamlp, "ArtifactResponse") : nullptr;
  if (!artifact_response) throw Failure("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse");
  std::string signed_response = verify_signed(artifact_response, idp.cert_ptrs(), "the ArtifactResponse");
  if (!signed_response.empty()) {
    result.xml = signed_response;
    result.doc = parse_xml(signed_response, "the signed ArtifactResponse");
    artifact_response = result.doc.root();
  }
  if (attr_of(artifact_response, "InResponseTo") != element_id) throw Failure("artifact", "the ArtifactResponse does not answer this ArtifactResolve");
  if (xmlNodePtr issuer = one_child(artifact_response, kNsSaml, "Issuer"); issuer && text_of(issuer) != idp.entity_id) {
    throw Failure("artifact", "the ArtifactResponse was issued by " + text_of(issuer));
  }
  xmlNodePtr status = one_child(artifact_response, kNsSamlp, "Status");
  std::string code;
  if (status) {
    if (xmlNodePtr code_el = one_child(status, kNsSamlp, "StatusCode")) code = attr_of(code_el, "Value");
    else code = attr_of(status, "Value");
  }
  if (code != kStatusSuccess) throw Failure("artifact", "the artifact resolution failed: " + (code.empty() ? "no status" : code));
  auto responses = child_elements(artifact_response, kNsSamlp, "Response");
  if (responses.empty()) throw Failure("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)");
  result.response = responses[0];
  return result;
}

std::map<std::string, std::string> form_of(const std::string& method, const std::string& body) {
  if (method != "POST") return {};
  if (body.empty()) return {};
  if (body.front() == '{') {
    Json parsed = parse_json(body);
    std::map<std::string, std::string> out;
    if (parsed.type == Json::Type::Object) {
      for (const auto& field : parsed.fields) {
        if (field.second.type == Json::Type::String) out[field.first] = field.second.text;
      }
    }
    return out;
  }
  return query_map(body);
}

}  // namespace

struct ServiceProvider::Impl {
  SpImpl core;
};

void SpImpl::refresh() {
  std::string source = config.idp_metadata;
  std::string xml;
  if (starts_with(source, "<")) xml = source;
  else if (starts_with(source, "http://") || starts_with(source, "https://")) {
    TlsOpt tls_store;
    const TlsOpt* tls = nullptr;
    if (!config.idp_ca.empty()) {
      tls_store.ca = config.idp_ca;
      tls = &tls_store;
    }
    HttpResult answer = http_send(source, "GET", {{"accept", "application/samlmetadata+xml, application/xml, text/xml"}}, "", tls, "metadata");
    if (answer.status != 200) throw Failure("metadata", source + " answered HTTP " + std::to_string(answer.status));
    xml = answer.body;
  } else {
    std::ifstream in(source, std::ios::binary);
    if (!in) throw Failure("metadata", "the identity provider metadata file " + source + " cannot be read");
    std::ostringstream buffer;
    buffer << in.rdbuf();
    xml = buffer.str();
  }
  idp = read_idp_metadata(xml, config.idp_entity_id);
  loaded = true;
}

const IdpInfo& SpImpl::require_idp() const {
  if (!loaded) throw Failure("metadata", "the identity provider's metadata has not been loaded");
  return idp;
}

ServiceProvider::ServiceProvider(std::unique_ptr<Impl> impl_in) : impl(std::move(impl_in)) {}
ServiceProvider::ServiceProvider(ServiceProvider&&) noexcept = default;
ServiceProvider& ServiceProvider::operator=(ServiceProvider&&) noexcept = default;
ServiceProvider::~ServiceProvider() = default;

ServiceProvider ServiceProvider::create(const std::string& config_json, const std::string& base_dir) {
  Json parsed = parse_json(config_json);
  auto impl = std::make_unique<Impl>();
  impl->core.config = resolve_config(parsed, base_dir);
  impl->core.refresh();
  return ServiceProvider(std::move(impl));
}

ServiceProvider ServiceProvider::from_file(const std::string& path, const std::map<std::string, std::string>& overrides) {
  auto impl = std::make_unique<Impl>();
  impl->core.config = read_config_file(path, overrides);
  impl->core.refresh();
  return ServiceProvider(std::move(impl));
}

LoginRequest ServiceProvider::login(const LoginOptions& options) {
  const IdpInfo& idp = impl->core.require_idp();
  std::string binding = options.request_binding.empty() ? impl->core.config.request_binding : options.request_binding;
  std::string response = options.response_binding.empty() ? impl->core.config.response_binding : options.response_binding;
  if (response == "artifact" && idp.artifact.empty()) throw Failure("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact");
  const std::string& destination = binding == "post" ? idp.sso_post : idp.sso_redirect;
  if (destination.empty()) {
    std::string which = binding == "post" ? "POST" : "Redirect";
    throw Failure("config", "the identity provider has no SingleSignOnService on HTTP-" + which);
  }
  if (options.relay_state && options.relay_state->size() > 80) throw Failure("config", "relayState is longer than the 80 bytes the bindings allow");
  std::string element_id = new_id();
  std::string force = options.force_authn ? " ForceAuthn=\"true\"" : "";
  std::string passive = options.passive ? " IsPassive=\"true\"" : "";
  std::string subject;
  if (options.subject_hint) {
    std::string form;
    if (options.subject_hint_format && !options.subject_hint_format->empty()) form = " Format=\"" + escape_xml(*options.subject_hint_format) + "\"";
    subject = "<saml:Subject><saml:NameID" + form + ">" + escape_xml(*options.subject_hint) + "</saml:NameID></saml:Subject>";
  }
  std::string policy = "<samlp:NameIDPolicy AllowCreate=\"true\"/>";
  if (!impl->core.config.name_id_format.empty()) policy = "<samlp:NameIDPolicy Format=\"" + escape_xml(impl->core.config.name_id_format) + "\" AllowCreate=\"true\"/>";
  std::string xml = "<samlp:AuthnRequest xmlns:samlp=\"" + std::string(kNsSamlp) + "\" xmlns:saml=\"" + kNsSaml + "\" ID=\"" + element_id + "\" Version=\"2.0\" IssueInstant=\"" + iso_now() +
                    "\" Destination=\"" + escape_xml(destination) + "\" AssertionConsumerServiceURL=\"" + escape_xml(impl->core.config.acs_url) + "\" ProtocolBinding=\"" + binding_uri(response) +
                    "\"" + force + passive + "><saml:Issuer>" + escape_xml(impl->core.config.entity_id) + "</saml:Issuer>" + subject + policy + "</samlp:AuthnRequest>";
  LoginRequest request;
  request.id = element_id;
  request.binding = binding;
  request.response_binding = response;
  if (binding == "redirect") {
    std::string query = redirect_query("SAMLRequest", xml, options.relay_state, impl->core.config.private_key.key);
    std::string join = destination.find('?') == std::string::npos ? "?" : "&";
    request.url = destination + join + query;
    request.xml = xml;
    return request;
  }
  std::string signed_xml = sign_enveloped(xml, element_id, impl->core.config.private_key.key, impl->core.config.certificate.cert);
  request.fields["SAMLRequest"] = b64_encode(signed_xml);
  std::vector<std::pair<std::string, std::string>> ordered{{"SAMLRequest", request.fields["SAMLRequest"]}};
  if (options.relay_state) {
    request.fields["RelayState"] = *options.relay_state;
    ordered.push_back({"RelayState", *options.relay_state});
  }
  request.url = destination;
  request.html = post_form_html(destination, ordered, options.nonce, "");
  request.xml = signed_xml;
  return request;
}

SamlLogin ServiceProvider::acs(const std::string& method, const std::string& raw_url, const std::string& body, const std::vector<std::string>& request_ids) {
  const IdpInfo& idp = impl->core.require_idp();
  std::string verb = method;
  for (char& c : verb) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  std::string raw_query = raw_query_of(raw_url);
  auto query = query_map(raw_query);
  auto form = form_of(verb, body);
  auto art_form = form.count("SAMLart") ? form["SAMLart"] : "";
  auto art_query = query.count("SAMLart") ? query["SAMLart"] : "";
  std::string art = !art_form.empty() ? art_form : art_query;
  if (!art.empty()) {
    ArtifactResult resolved = resolve_artifact_doc(art, impl->core.config, idp);
    Received received;
    received.xml = resolved.xml;
    received.response = resolved.response;
    received.binding = "artifact";
    received.authenticated_by_binding = true;
    if (!art_form.empty()) {
      if (form.count("RelayState")) received.relay_state = form["RelayState"];
    } else if (query.count("RelayState")) received.relay_state = query["RelayState"];
    return validate_response(received, impl->core.config, idp, impl->core.replay, request_ids);
  }
  if (verb == "POST" && form.count("SAMLResponse") && !form["SAMLResponse"].empty()) {
    std::string xml = read_post(form["SAMLResponse"], "SAMLResponse");
    XmlDoc doc = parse_xml(xml, "the Response");
    Received received;
    received.xml = xml;
    received.response = doc.root();
    received.binding = "post";
    if (form.count("RelayState")) received.relay_state = form["RelayState"];
    return validate_response(received, impl->core.config, idp, impl->core.replay, request_ids);
  }
  if (query.count("SAMLResponse") && !query["SAMLResponse"].empty()) {
    RedirectMessage message = read_redirect(raw_query, "SAMLResponse", idp.cert_ptrs());
    XmlDoc doc = parse_xml(message.xml, "the Response");
    Received received;
    received.xml = message.xml;
    received.response = doc.root();
    received.binding = "redirect";
    received.relay_state = message.relay_state;
    received.authenticated_by_binding = message.signed_ok;
    return validate_response(received, impl->core.config, idp, impl->core.replay, request_ids);
  }
  throw Failure("binding", "the request carries no SAMLResponse or SAMLart");
}

std::string ServiceProvider::metadata() const { return write_sp_metadata(impl->core.config.entity_id, impl->core.config.acs_url, impl->core.config.certificate.cert, impl->core.config.want_assertions_signed, impl->core.config.name_id_format); }
const std::string& ServiceProvider::entity_id() const { return impl->core.config.entity_id; }
const std::string& ServiceProvider::acs_url() const { return impl->core.config.acs_url; }
const std::string& ServiceProvider::request_binding() const { return impl->core.config.request_binding; }
const std::string& ServiceProvider::response_binding() const { return impl->core.config.response_binding; }
bool ServiceProvider::want_assertions_signed() const { return impl->core.config.want_assertions_signed; }
bool ServiceProvider::want_assertions_encrypted() const { return impl->core.config.want_assertions_encrypted; }
bool ServiceProvider::allow_unsolicited() const { return impl->core.config.allow_unsolicited; }
std::int64_t ServiceProvider::clock_skew_ms() const { return impl->core.config.clock_skew_ms; }
bool ServiceProvider::has_signals() const { return impl->core.config.signals_present; }
std::optional<bool> ServiceProvider::signals() const {
  if (!impl->core.config.signals_present) return std::nullopt;
  return impl->core.config.signals_value;
}
const std::string& ServiceProvider::idp_entity_id() const { return impl->core.idp.entity_id; }
const std::string* ServiceProvider::idp_sso(const std::string& binding) const {
  const std::string& value = binding == "post" ? impl->core.idp.sso_post : impl->core.idp.sso_redirect;
  return value.empty() ? nullptr : &value;
}
int ServiceProvider::idp_certificate_count() const { return static_cast<int>(impl->core.idp.certs.size()); }
const std::string& ServiceProvider::certificate_pem() const { return impl->core.config.certificate_pem; }
const std::string& ServiceProvider::private_key_pem() const { return impl->core.config.private_key_pem; }
const std::string& ServiceProvider::idp_ca() const { return impl->core.config.idp_ca; }

KeyPair create_key_pair(const std::string& common_name, int days, int bits) { return make_key_pair(common_name, days, bits); }

KeyDestination key_destination(const std::string& config_path, const std::string& key, const std::string& cert, const std::string& common_name) {
  KeyDestination out;
  out.key_path = key;
  out.cert_path = cert;
  out.common_name = common_name;
  return out;
}

std::string metadata_for_config(const std::string& path, const std::string& entity_id, const std::string& acs_url) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Failure("config", path + " cannot be read");
  std::ostringstream buffer;
  buffer << in.rdbuf();
  Json parsed = parse_json(buffer.str());
  std::vector<std::pair<std::string, Json>> kept;
  for (auto& field : parsed.fields) {
    if (field.first == "idpCa") continue;
    if (field.first == "entityId" && !entity_id.empty()) {
      field.second.type = Json::Type::String;
      field.second.text = entity_id;
    }
    if (field.first == "acsUrl" && !acs_url.empty()) {
      field.second.type = Json::Type::String;
      field.second.text = acs_url;
    }
    kept.push_back(std::move(field));
  }
  if (!entity_id.empty() && !parsed.has("entityId")) {
    Json value;
    value.type = Json::Type::String;
    value.text = entity_id;
    kept.emplace_back("entityId", value);
  }
  if (!acs_url.empty() && !parsed.has("acsUrl")) {
    Json value;
    value.type = Json::Type::String;
    value.text = acs_url;
    kept.emplace_back("acsUrl", value);
  }
  parsed.fields = std::move(kept);
  std::filesystem::path abs = std::filesystem::absolute(path);
  ResolvedConfig cfg = resolve_config(parsed, abs.parent_path().string());
  return write_sp_metadata(cfg.entity_id, cfg.acs_url, cfg.certificate.cert, cfg.want_assertions_signed, cfg.name_id_format);
}

IdpDescription describe_idp(const std::string& metadata_xml) {
  IdpInfo info = read_idp_metadata(metadata_xml, "");
  IdpDescription out;
  out.entity_id = info.entity_id;
  out.sso = !info.sso_redirect.empty() ? info.sso_redirect : info.sso_post;
  for (const auto& item : info.artifact) out.artifact_services.push_back(item.second);
  return out;
}

std::string resolve_artifact(const std::string&, const ResolvedConfig&, const IdpInfo&, xmlNodePtr&, std::string&) { return ""; }

ArtifactResolveView read_artifact_resolve(const std::string& xml, const std::string& cert_pem) {
  ArtifactResolveView view;
  XmlDoc doc = parse_xml(xml, "the ArtifactResolve");
  auto found = descendant_elements(doc.root(), kNsSamlp, "ArtifactResolve");
  if (found.empty()) return view;
  xmlNodePtr body = found[0];
  view.id = attr_of(body, "ID");
  auto arts = child_elements(body, kNsSamlp, "Artifact");
  if (!arts.empty()) view.artifact = trim_copy(iter_text(arts[0]));
  try {
    OwnedCert cert = load_certificate(cert_pem);
    std::string signed_form = verify_signed(body, {cert.cert}, "the ArtifactResolve");
    view.signature_ok = !signed_form.empty();
  } catch (...) {
    view.signature_ok = false;
  }
  return view;
}

}  // namespace iya::saml
