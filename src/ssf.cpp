// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <utility>

namespace iya::saml {
namespace {

const char* kCaep = "https://schemas.openid.net/secevent/caep/event-type/";
const char* kRisc = "https://schemas.openid.net/secevent/risc/event-type/";
const char* kSsf = "https://schemas.openid.net/secevent/ssf/event-type/";

const std::vector<std::pair<const char*, const char*>>& table() {
  static const std::vector<std::pair<const char*, const char*>> rows = {
      {"session_revoked", "https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
      {"token_claims_change", "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"},
      {"credential_change", "https://schemas.openid.net/secevent/caep/event-type/credential-change"},
      {"assurance_level_change", "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"},
      {"device_compliance_change", "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"},
      {"session_established", "https://schemas.openid.net/secevent/caep/event-type/session-established"},
      {"session_presented", "https://schemas.openid.net/secevent/caep/event-type/session-presented"},
      {"risk_level_change", "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"},
      {"account_credential_change_required", "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"},
      {"account_purged", "https://schemas.openid.net/secevent/risc/event-type/account-purged"},
      {"account_disabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
      {"account_enabled", "https://schemas.openid.net/secevent/risc/event-type/account-enabled"},
      {"identifier_changed", "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"},
      {"identifier_recycled", "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"},
      {"credential_compromise", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"},
      {"opt_in", "https://schemas.openid.net/secevent/risc/event-type/opt-in"},
      {"opt_out_initiated", "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"},
      {"opt_out_cancelled", "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"},
      {"opt_out_effective", "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"},
      {"recovery_activated", "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"},
      {"recovery_information_changed", "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"},
      {"sessions_revoked", "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"},
      {"verification", "https://schemas.openid.net/secevent/ssf/event-type/verification"},
      {"stream_updated", "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"},
  };
  return rows;
}

std::string string_of(const Json* value) {
  if (!value || value->type != Json::Type::String) return "";
  return value->text;
}

Json jstr(const std::string& text) {
  Json out;
  out.type = Json::Type::String;
  out.text = text;
  return out;
}

Json jbool(bool value) {
  Json out;
  out.type = Json::Type::Bool;
  out.b = value;
  return out;
}

Json jnum(long long value) {
  Json out;
  out.type = Json::Type::Number;
  out.num = static_cast<double>(value);
  out.text = std::to_string(value);
  return out;
}

Json jarr(std::vector<Json> items) {
  Json out;
  out.type = Json::Type::Array;
  out.items = std::move(items);
  return out;
}

Json jobj(std::vector<std::pair<std::string, Json>> fields) {
  Json out;
  out.type = Json::Type::Object;
  out.fields = std::move(fields);
  return out;
}

std::string clip(const std::string& text) { return text.size() > 300 ? text.substr(0, 300) : text; }

Json parse_body(const std::string& body) {
  if (body.empty()) return Json();
  try {
    return parse_json(body);
  } catch (const Failure&) {
    return jstr(body);
  }
}

const char* kty_of(const std::string& alg) {
  if (alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "PS256" || alg == "PS384" || alg == "PS512") return "RSA";
  if (alg == "ES256" || alg == "ES384" || alg == "ES512") return "EC";
  if (alg == "EdDSA" || alg == "Ed25519") return "OKP";
  return "";
}

bool known_alg(const std::string& alg) { return kty_of(alg)[0] != '\0'; }

std::map<std::string, std::string> simple_subject(const Json* identifier, const std::string& issuer) {
  std::map<std::string, std::string> out;
  if (!identifier || identifier->type != Json::Type::Object) return out;
  std::string form = string_of(identifier->find("format"));
  if (form.empty()) form = string_of(identifier->find("subject_type"));
  if (form == "iss_sub") {
    std::string sub = string_of(identifier->find("sub"));
    const Json* iss = identifier->find("iss");
    bool iss_ok = iss == nullptr || iss->type == Json::Type::Null || string_of(iss) == issuer;
    if (!sub.empty() && iss_ok) out["sub"] = sub;
  } else if (form == "email") {
    std::string email = string_of(identifier->find("email"));
    if (!email.empty()) out["email"] = email;
  } else if (form == "opaque") {
    std::string id = string_of(identifier->find("id"));
    if (!id.empty()) out["opaque"] = id;
  } else if (form == "aliases") {
    const Json* items = identifier->find("identifiers");
    if (items && items->type == Json::Type::Array) {
      for (const Json& item : items->items) {
        for (const auto& pair : simple_subject(&item, issuer)) out[pair.first] = pair.second;
      }
    }
  }
  return out;
}

std::vector<std::string> audience_of(const Json* value) {
  std::vector<std::string> out;
  if (!value || value->type == Json::Type::Null) return out;
  if (value->type == Json::Type::String) {
    if (!value->text.empty()) out.push_back(value->text);
    return out;
  }
  if (value->type == Json::Type::Array) {
    for (const Json& item : value->items) out.push_back(string_of(&item));
    return out;
  }
  if (value->type == Json::Type::Number) out.push_back(value->text.empty() ? std::to_string(value->num) : value->text);
  else if (value->type == Json::Type::Bool) out.push_back(value->b ? "true" : "false");
  return out;
}

}  // namespace

const std::vector<std::pair<const char*, const char*>>& event_table() { return table(); }

std::vector<std::string> events_with_prefix(const char* prefix) {
  std::vector<std::string> out;
  std::string want = prefix ? prefix : "";
  for (const auto& row : table()) {
    std::string value = row.second;
    if (value.size() >= want.size() && value.compare(0, want.size(), want) == 0) out.push_back(value);
  }
  return out;
}

std::vector<std::string> default_events_requested() {
  return {event_uri("session_revoked"),
          event_uri("credential_change"),
          event_uri("assurance_level_change"),
          event_uri("token_claims_change"),
          event_uri("account_disabled"),
          event_uri("account_enabled"),
          event_uri("account_purged"),
          event_uri("credential_compromise"),
          event_uri("sessions_revoked"),
          event_uri("account_credential_change_required")};
}

std::vector<std::string> default_ending_events() {
  return {event_uri("session_revoked"), event_uri("account_disabled"), event_uri("account_purged"), event_uri("credential_compromise"),
          event_uri("sessions_revoked")};
}

std::vector<std::string> caep_events() { return events_with_prefix(kCaep); }
std::vector<std::string> risc_events() { return events_with_prefix(kRisc); }

const char* event_uri(const char* name) {
  if (!name) return "";
  for (const auto& row : table()) {
    if (std::strcmp(row.first, name) == 0) return row.second;
  }
  return "";
}

std::map<std::string, std::string> subject_of(const Json& sub_id, const std::string& issuer) {
  std::map<std::string, std::string> out;
  if (sub_id.type != Json::Type::Object) return out;
  std::string form = string_of(sub_id.find("format"));
  if (form.empty()) form = string_of(sub_id.find("subject_type"));
  bool complex = form == "complex" || (form.empty() && (sub_id.find("user") || sub_id.find("session")));
  if (complex) {
    auto user = simple_subject(sub_id.find("user"), issuer);
    auto session = simple_subject(sub_id.find("session"), issuer);
    if (!user["sub"].empty()) out["person"] = user["sub"];
    if (!user["email"].empty()) out["email"] = user["email"];
    std::string session_id = session["opaque"];
    if (session_id.empty()) session_id = session["sub"];
    if (!session_id.empty()) out["idp_session"] = session_id;
    return out;
  }
  auto one = simple_subject(&sub_id, issuer);
  if (!one["sub"].empty()) out["person"] = one["sub"];
  if (!one["email"].empty()) out["email"] = one["email"];
  return out;
}

SessionIndex::SessionIndex(int max_entries) : max_(max_entries > 0 ? max_entries : 100000) {}

void SessionIndex::drop_locked(const std::string& local_id) {
  sessions_.erase(local_id);
  std::vector<std::string> next;
  for (const std::string& id : order_) {
    if (id != local_id) next.push_back(id);
  }
  order_ = std::move(next);
}

void SessionIndex::add(SessionRecord record) {
  std::lock_guard<std::mutex> lock(mu_);
  if (!sessions_.count(record.local_id) && static_cast<int>(sessions_.size()) >= max_) {
    auto now = unix_ms(std::chrono::system_clock::now());
    std::vector<std::string> expired;
    for (const std::string& key : order_) {
      const SessionRecord& value = sessions_[key];
      if (value.expires && unix_ms(*value.expires) <= now) expired.push_back(key);
    }
    for (const std::string& key : expired) drop_locked(key);
    while (static_cast<int>(sessions_.size()) >= max_ && !order_.empty()) drop_locked(order_.front());
  }
  if (!record.email.empty()) record.email = lower_copy(record.email);
  if (!sessions_.count(record.local_id)) order_.push_back(record.local_id);
  sessions_[record.local_id] = std::move(record);
}

void SessionIndex::remove(const std::string& local_id) {
  std::lock_guard<std::mutex> lock(mu_);
  drop_locked(local_id);
}

std::vector<std::string> SessionIndex::find(const std::function<bool(const SessionRecord&)>& match) const {
  auto now = unix_ms(std::chrono::system_clock::now());
  std::vector<std::string> out;
  std::vector<std::string> keep;
  for (const std::string& key : order_) {
    auto found = sessions_.find(key);
    if (found == sessions_.end()) continue;
    if (found->second.expires && unix_ms(*found->second.expires) <= now) {
      sessions_.erase(found);
      continue;
    }
    keep.push_back(key);
    if (match(found->second)) out.push_back(key);
  }
  order_ = std::move(keep);
  return out;
}

std::vector<std::string> SessionIndex::by_person(const std::string& person) const {
  std::lock_guard<std::mutex> lock(mu_);
  return find([&](const SessionRecord& session) { return session.person == person; });
}

std::vector<std::string> SessionIndex::by_email(const std::string& email) const {
  std::string wanted = lower_copy(email);
  std::lock_guard<std::mutex> lock(mu_);
  return find([&](const SessionRecord& session) { return session.email == wanted; });
}

std::vector<std::string> SessionIndex::by_idp_session(const std::string& idp_session) const {
  std::lock_guard<std::mutex> lock(mu_);
  return find([&](const SessionRecord& session) { return session.idp_session == idp_session; });
}

SessionRecord tracked_from(const std::string& local_id, const SamlLogin& login, const std::string& subject_attribute,
                           std::optional<std::chrono::system_clock::time_point> expires) {
  std::string attribute = subject_attribute.empty() ? kDefaultSubject : subject_attribute;
  SessionRecord record;
  record.local_id = local_id;
  auto person = login.attributes.find(attribute);
  if (person != login.attributes.end() && !person->second.empty()) record.person = person->second.front();
  static const char* mail_names[] = {"urn:oid:0.9.2342.19200300.100.1.3", "mail", "email",
                                     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"};
  for (const char* name : mail_names) {
    auto found = login.attributes.find(name);
    if (found != login.attributes.end() && !found->second.empty() && !found->second.front().empty()) {
      record.email = found->second.front();
      break;
    }
  }
  if (record.email.empty() && login.name_id_format == kEmailNameId) record.email = login.name_id;
  record.idp_session = login.session_index;
  record.expires = expires ? expires : login.session_not_on_or_after;
  return record;
}

std::string verify_compact_jws(const std::string& token, const std::vector<Json>& keys, Json& header_out, Json& payload_out) {
  std::vector<std::string> parts;
  size_t start = 0;
  for (size_t i = 0; i <= token.size(); i++) {
    if (i == token.size() || token[i] == '.') {
      parts.push_back(token.substr(start, i - start));
      start = i + 1;
    }
  }
  if (parts.size() != 3) throw Failure("signature", "the SET is not a compact JWS");
  std::string header_raw = b64url_decode(parts[0], "header");
  std::string payload_raw = b64url_decode(parts[1], "payload");
  try {
    header_out = parse_json(header_raw);
    payload_out = parse_json(payload_raw);
  } catch (const Failure& failure) {
    throw Failure("signature", std::string("the SET's header or payload is not JSON: ") + failure.what());
  }
  if (header_out.type != Json::Type::Object || payload_out.type != Json::Type::Object) {
    throw Failure("signature", "the SET's header or payload is not a JSON object");
  }
  std::string alg = string_of(header_out.find("alg"));
  if (!known_alg(alg)) {
    std::string shown = alg.empty() ? "(no alg)" : alg;
    throw Failure("signature", "the SET is signed with " + shown +
                                   ", which this receiver does not verify (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519)");
  }
  if (header_out.has("crit")) throw Failure("signature", "the SET's header has a crit member this receiver does not understand");
  std::string kid = string_of(header_out.find("kid"));
  const char* kty = kty_of(alg);
  std::vector<const Json*> candidates;
  for (const Json& key : keys) {
    if (!kid.empty() && key.str_or("kid") != kid) continue;
    if (key.str_or("kty") != kty) continue;
    std::string use = key.str_or("use");
    if (!use.empty() && use != "sig") continue;
    std::string key_alg = key.str_or("alg");
    if (!key_alg.empty() && key_alg != alg) continue;
    candidates.push_back(&key);
  }
  if (candidates.empty()) {
    std::string which = kid.empty() ? "" : " with kid " + kid;
    throw Failure("signature", std::string("the transmitter publishes no ") + kty + " signing key" + which);
  }
  std::string signature = b64url_decode(parts[2], "signature");
  std::string data = parts[0] + "." + parts[1];
  for (const Json* jwk : candidates) {
    try {
      OwnedKey key = jwk_to_key(*jwk);
      if (jws_verify(key.key, alg, data, signature)) return payload_raw;
    } catch (const Failure&) {
    }
  }
  throw Failure("signature", "the SET's signature does not verify against the transmitter's keys");
}

namespace {

void log_line(const ReceiverImpl& receiver, const std::string& level, const std::string& message) {
  if (receiver.log) receiver.log(level, message);
  else {
    std::printf("%s\n", message.c_str());
    std::fflush(stdout);
  }
}

struct CallAnswer {
  int status = 0;
  Json body;
};

CallAnswer call_transmitter(ReceiverImpl& receiver, const std::string& method, const std::string& url, const Json* body) {
  std::vector<std::pair<std::string, std::string>> headers{{"accept", "application/json"}};
  std::string payload;
  if (body) {
    headers.emplace_back("content-type", "application/json");
    payload = json_dump(*body);
  }
  const TlsOpt* tls = receiver.has_tls ? &receiver.tls : nullptr;
  HttpResult answer = http_send(url, method, headers, payload, tls, "ssf");
  CallAnswer out;
  out.status = answer.status;
  out.body = parse_body(answer.body);
  return out;
}

Json discover_transmitter(ReceiverImpl& receiver) {
  std::string url = receiver.transmitter + "/.well-known/ssf-configuration";
  CallAnswer answer = call_transmitter(receiver, "GET", url, nullptr);
  if (answer.status != 200 || answer.body.type != Json::Type::Object || answer.body.str_or("configuration_endpoint").empty() ||
      answer.body.str_or("jwks_uri").empty()) {
    throw Failure("ssf", url + " answered " + std::to_string(answer.status) + " without a usable transmitter configuration");
  }
  const Json* supported = answer.body.find("delivery_methods_supported");
  if (supported && supported->type == Json::Type::Array && !supported->items.empty()) {
    bool found = false;
    for (const Json& item : supported->items) {
      if (string_of(&item) == kPollMethod) found = true;
    }
    if (!found) throw Failure("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
  }
  return answer.body;
}

std::vector<Json> load_jwks(ReceiverImpl& receiver, bool force) {
  std::string uri;
  {
    std::lock_guard<std::mutex> lock(receiver.mu);
    if (!force && !receiver.keys.empty() && std::chrono::steady_clock::now() - receiver.keys_at < std::chrono::hours(1)) return receiver.keys;
    uri = receiver.config.str_or("jwks_uri");
  }
  CallAnswer answer = call_transmitter(receiver, "GET", uri, nullptr);
  const Json* raw = answer.body.type == Json::Type::Object ? answer.body.find("keys") : nullptr;
  if (answer.status != 200 || !raw || raw->type != Json::Type::Array) {
    throw Failure("ssf", "the transmitter's JWKS answered " + std::to_string(answer.status));
  }
  std::vector<Json> keys;
  for (const Json& item : raw->items) {
    if (item.type == Json::Type::Object) keys.push_back(item);
  }
  std::lock_guard<std::mutex> lock(receiver.mu);
  receiver.keys = keys;
  receiver.keys_at = std::chrono::steady_clock::now();
  return keys;
}

Json ensure_stream(ReceiverImpl& receiver) {
  std::string endpoint;
  {
    std::lock_guard<std::mutex> lock(receiver.mu);
    endpoint = receiver.config.str_or("configuration_endpoint");
  }
  CallAnswer listed = call_transmitter(receiver, "GET", endpoint, nullptr);
  if (listed.status == 200) {
    std::vector<const Json*> all;
    if (listed.body.type == Json::Type::Array) {
      for (const Json& item : listed.body.items) all.push_back(&item);
    } else if (listed.body.type == Json::Type::Object) {
      all.push_back(&listed.body);
    }
    for (const Json* item : all) {
      if (item->type != Json::Type::Object || item->str_or("stream_id").empty()) continue;
      const Json* delivery = item->find("delivery");
      if (delivery && string_of(delivery->find("method")) == kPollMethod) return *item;
    }
  } else if (listed.status != 404) {
    throw Failure("ssf", "listing the streams at " + endpoint + " answered " + std::to_string(listed.status) + ": " + clip(json_dump(listed.body)));
  }
  std::vector<Json> requested;
  for (const std::string& item : receiver.events_requested) requested.push_back(jstr(item));
  std::vector<std::pair<std::string, Json>> fields;
  fields.emplace_back("delivery", jobj({{"method", jstr(kPollMethod)}}));
  fields.emplace_back("events_requested", jarr(std::move(requested)));
  if (!receiver.description.empty()) fields.emplace_back("description", jstr(receiver.description));
  Json body = jobj(std::move(fields));
  CallAnswer created = call_transmitter(receiver, "POST", endpoint, &body);
  if ((created.status != 200 && created.status != 201) || created.body.type != Json::Type::Object || created.body.str_or("stream_id").empty()) {
    throw Failure("ssf", "creating a stream at " + endpoint + " answered " + std::to_string(created.status) + ": " + clip(json_dump(created.body)));
  }
  return created.body;
}

std::vector<std::string> sessions_for(ReceiverImpl& receiver, const std::string& event_type, const std::map<std::string, std::string>& subject) {
  if (event_type == event_uri("verification") || event_type == event_uri("stream_updated")) return {};
  auto idp_session = subject.find("idp_session");
  if (idp_session != subject.end() && !idp_session->second.empty()) {
    auto found = receiver.index.by_idp_session(idp_session->second);
    if (!found.empty() || event_type == event_uri("session_revoked")) return found;
  }
  auto person = subject.find("person");
  if (person != subject.end() && !person->second.empty()) return receiver.index.by_person(person->second);
  auto email = subject.find("email");
  if (email != subject.end() && !email->second.empty()) return receiver.index.by_email(email->second);
  return {};
}

void handle_set(ReceiverImpl& receiver, const std::string& jti, const std::string& token) {
  std::vector<Json> keys = load_jwks(receiver, false);
  Json header;
  Json payload;
  std::string raw_payload;
  try {
    raw_payload = verify_compact_jws(token, keys, header, payload);
  } catch (const Failure& failure) {
    if (failure.what() && (std::string(failure.what()).find("publishes no") != std::string::npos ||
                           std::string(failure.what()).find("does not verify") != std::string::npos)) {
      try {
        keys = load_jwks(receiver, true);
        raw_payload = verify_compact_jws(token, keys, header, payload);
      } catch (const Failure&) {
        throw failure;
      }
    } else {
      throw;
    }
  }
  (void)raw_payload;
  if (header.find("typ") && lower_copy(string_of(header.find("typ"))) != "secevent+jwt") {
    throw Failure("validation", "the SET's typ is " + string_of(header.find("typ")));
  }
  std::string issuer;
  Json want;
  {
    std::lock_guard<std::mutex> lock(receiver.mu);
    issuer = receiver.config.str_or("issuer");
    if (const Json* aud = receiver.stream.find("aud")) want = *aud;
  }
  if (string_of(payload.find("iss")) != issuer) {
    throw Failure("validation", "the SET was issued by " + string_of(payload.find("iss")) + ", not " + issuer);
  }
  std::vector<std::string> wanted = audience_of(&want);
  std::vector<std::string> audience = audience_of(payload.find("aud"));
  if (!wanted.empty()) {
    bool match = false;
    for (const std::string& item : audience) {
      for (const std::string& allowed : wanted) {
        if (item == allowed) match = true;
      }
    }
    if (!match) throw Failure("validation", "the SET is for " + join_strings(audience, ", ") + ", not this stream");
  }
  if (payload.find("jti") && string_of(payload.find("jti")) != jti) {
    throw Failure("validation", "the SET's jti is not the one it was delivered under");
  }
  const Json* events = payload.find("events");
  if (!events || events->type != Json::Type::Object || events->fields.empty()) throw Failure("validation", "the SET carries no events");
  for (const auto& field : events->fields) {
    const Json* body = field.second.type == Json::Type::Object ? &field.second : nullptr;
    Json subject_source;
    bool have_subject = false;
    if (payload.find("sub_id")) {
      subject_source = *payload.find("sub_id");
      have_subject = true;
    } else if (body && body->find("subject")) {
      subject_source = *body->find("subject");
      have_subject = true;
    }
    auto subject = have_subject ? subject_of(subject_source, issuer) : std::map<std::string, std::string>{};
    auto sessions = sessions_for(receiver, field.first, subject);
    bool ends = receiver.end_on.count(field.first) && receiver.end_on[field.first] && !sessions.empty();
    SignalEvent event;
    event.type = field.first;
    event.jti = jti;
    event.sessions = sessions;
    event.ended = ends;
    event.subject = subject;
    event.payload_json = json_dump(body ? *body : Json());
    if (ends) {
      try {
        if (receiver.on_end) receiver.on_end(sessions, event);
      } catch (const std::exception& ex) {
        log_line(receiver, "error", "ssf: onEndSessions threw for " + field.first + " (SET " + jti + " is still acknowledged): " + ex.what());
        event.ended = false;
      }
      if (event.ended) {
        for (const std::string& local_id : sessions) receiver.index.remove(local_id);
      }
    }
    std::vector<std::function<void(SignalEvent&)>> handlers;
    {
      std::lock_guard<std::mutex> lock(receiver.mu);
      auto typed = receiver.handlers.find(field.first);
      if (typed != receiver.handlers.end()) handlers.insert(handlers.end(), typed->second.begin(), typed->second.end());
      auto star = receiver.handlers.find("*");
      if (star != receiver.handlers.end()) handlers.insert(handlers.end(), star->second.begin(), star->second.end());
    }
    for (auto& handler : handlers) {
      try {
        handler(event);
      } catch (const std::exception& ex) {
        log_line(receiver, "error", "ssf: a handler for " + field.first + " threw (SET " + jti + " is still acknowledged): " + ex.what());
      }
    }
  }
}

bool poll_now(ReceiverImpl& receiver) {
  std::string url;
  std::vector<std::string> ack;
  std::map<std::string, Json> set_errs;
  {
    std::lock_guard<std::mutex> lock(receiver.mu);
    const Json* delivery = receiver.stream.find("delivery");
    if (delivery) url = delivery->str_or("endpoint_url");
    ack = receiver.ack;
    receiver.ack.clear();
    set_errs = receiver.errs;
    receiver.errs.clear();
  }
  std::vector<std::pair<std::string, Json>> fields;
  fields.emplace_back("maxEvents", jnum(receiver.max_events));
  fields.emplace_back("returnImmediately", jbool(true));
  if (!ack.empty()) {
    std::vector<Json> items;
    for (const std::string& item : ack) items.push_back(jstr(item));
    fields.emplace_back("ack", jarr(std::move(items)));
  }
  if (!set_errs.empty()) {
    std::vector<std::pair<std::string, Json>> err_fields;
    for (const auto& item : set_errs) err_fields.push_back(item);
    fields.emplace_back("setErrs", jobj(std::move(err_fields)));
  }
  Json body = jobj(std::move(fields));
  CallAnswer answer;
  bool failed = false;
  Failure cause("ssf", "");
  try {
    answer = call_transmitter(receiver, "POST", url, &body);
  } catch (const Failure& failure) {
    failed = true;
    cause = failure;
  }
  if (failed || answer.status != 200) {
    std::lock_guard<std::mutex> lock(receiver.mu);
    ack.insert(ack.end(), receiver.ack.begin(), receiver.ack.end());
    receiver.ack = std::move(ack);
    for (const auto& item : receiver.errs) set_errs[item.first] = item.second;
    receiver.errs = std::move(set_errs);
    if (failed) throw cause;
    throw Failure("ssf", "the poll answered " + std::to_string(answer.status) + ": " + clip(json_dump(answer.body)));
  }
  const Json* sets = answer.body.type == Json::Type::Object ? answer.body.find("sets") : nullptr;
  if (sets && sets->type == Json::Type::Object) {
    for (const auto& field : sets->fields) {
      try {
        handle_set(receiver, field.first, string_of(&field.second));
        std::lock_guard<std::mutex> lock(receiver.mu);
        receiver.ack.push_back(field.first);
      } catch (const std::exception& ex) {
        log_line(receiver, "warn", std::string("ssf: SET ") + field.first + " refused: " + ex.what());
        std::string kind = "invalid_request";
        if (const auto* failure = dynamic_cast<const Failure*>(&ex); failure && failure->kind == "signature") kind = "invalid_key";
        Json err = jobj({{"err", jstr(kind)}, {"description", jstr(ex.what())}});
        std::lock_guard<std::mutex> lock(receiver.mu);
        receiver.errs[field.first] = std::move(err);
      }
    }
  }
  const Json* more = answer.body.type == Json::Type::Object ? answer.body.find("moreAvailable") : nullptr;
  return more && more->type == Json::Type::Bool && more->b;
}

}  // namespace

bool ReceiverImpl::poll_once() {
  std::shared_ptr<Flight> mine;
  {
    std::unique_lock<std::mutex> lock(sched);
    if (flight) {
      std::shared_ptr<Flight> current = flight;
      lock.unlock();
      std::unique_lock<std::mutex> wait(current->mu);
      current->cv.wait(wait, [&] { return current->done; });
      if (current->err) std::rethrow_exception(current->err);
      return current->result;
    }
    mine = std::make_shared<Flight>();
    flight = mine;
  }
  bool result = false;
  std::exception_ptr error;
  try {
    result = poll_now(*this);
  } catch (...) {
    error = std::current_exception();
  }
  {
    std::lock_guard<std::mutex> lock(sched);
    if (flight == mine) flight.reset();
    std::lock_guard<std::mutex> done(mine->mu);
    mine->done = true;
    mine->result = result;
    mine->err = error;
    mine->cv.notify_all();
  }
  if (error) std::rethrow_exception(error);
  return result;
}

void ReceiverImpl::cycle() {
  int delay = poll_interval_ms;
  {
    std::lock_guard<std::mutex> lock(sched);
    if (!running) return;
    inflight++;
  }
  try {
    if (poll_once()) delay = 0;
  } catch (const std::exception& ex) {
    log_line(*this, "warn", std::string("ssf: poll failed: ") + ex.what());
    delay = poll_interval_ms * 4;
    if (delay > 60000) delay = 60000;
  }
  {
    std::lock_guard<std::mutex> lock(sched);
    inflight--;
    next_delay_ms = delay;
    if (running && !worker_started) {
      worker_started = true;
      worker = std::thread([this] {
        for (;;) {
          int wait_ms = 0;
          {
            std::unique_lock<std::mutex> worker_lock(sched);
            if (!running) return;
            wait_ms = next_delay_ms;
          }
          if (wait_ms > 0) {
            std::unique_lock<std::mutex> worker_lock(sched);
            cv.wait_for(worker_lock, std::chrono::milliseconds(wait_ms), [this] { return !running; });
            if (!running) return;
          }
          cycle();
        }
      });
    }
    cv.notify_all();
  }
}

void ReceiverImpl::start() {
  {
    std::lock_guard<std::mutex> lock(sched);
    if (running) return;
  }
  Json discovered = discover_transmitter(*this);
  {
    std::lock_guard<std::mutex> lock(mu);
    config = std::move(discovered);
  }
  load_jwks(*this, true);
  Json created = ensure_stream(*this);
  const Json* delivery = created.find("delivery");
  if (!delivery || delivery->str_or("endpoint_url").empty()) throw Failure("ssf", "the stream has no poll endpoint_url");
  std::string stream_id = created.str_or("stream_id");
  std::string endpoint = delivery->str_or("endpoint_url");
  int delivered = 0;
  if (const Json* list = created.find("events_delivered"); list && list->type == Json::Type::Array) delivered = static_cast<int>(list->items.size());
  {
    std::lock_guard<std::mutex> data(mu);
    stream = std::move(created);
  }
  {
    std::lock_guard<std::mutex> lock(sched);
    if (running) return;
    running = true;
  }
  log_line(*this, "info", "ssf: polling stream " + stream_id + " at " + endpoint + ", delivering " + std::to_string(delivered) + " event type(s)");
  cycle();
}

void ReceiverImpl::stop() {
  std::thread joined;
  {
    std::unique_lock<std::mutex> lock(sched);
    running = false;
    cv.notify_all();
    cv.wait(lock, [this] { return inflight == 0; });
    if (worker_started) {
      joined = std::move(worker);
      worker_started = false;
    }
  }
  if (joined.joinable()) joined.join();
}

std::string ReceiverImpl::stream_id() const {
  std::lock_guard<std::mutex> lock(mu);
  return stream.str_or("stream_id");
}

struct SignalsReceiver::Impl {
  ReceiverImpl core;
};

SignalsReceiver::SignalsReceiver(std::unique_ptr<Impl> impl_in) : impl(std::move(impl_in)) {}
SignalsReceiver::SignalsReceiver(SignalsReceiver&&) noexcept = default;
SignalsReceiver& SignalsReceiver::operator=(SignalsReceiver&&) noexcept = default;
SignalsReceiver::~SignalsReceiver() {
  if (impl) impl->core.stop();
}

SignalsReceiver SignalsReceiver::create(ReceiverOptions options) {
  if (!options.on_end_sessions) throw Failure("config", "onEndSessions is required");
  if (!starts_with(options.transmitter, "http://") && !starts_with(options.transmitter, "https://")) {
    throw Failure("config", "transmitter must be an http(s) URL");
  }
  auto impl = std::make_unique<Impl>();
  ReceiverImpl& core = impl->core;
  core.transmitter = options.transmitter;
  while (!core.transmitter.empty() && core.transmitter.back() == '/') core.transmitter.pop_back();
  core.on_end = std::move(options.on_end_sessions);
  core.tls.ca = options.tls_ca;
  core.tls.cert = options.tls_cert;
  core.tls.key = options.tls_key;
  core.has_tls = !options.tls_cert.empty() || !options.tls_key.empty() || !options.tls_ca.empty();
  core.events_requested = default_events_requested();
  for (const std::string& item : default_ending_events()) core.end_on[item] = true;
  core.subject_attribute = kDefaultSubject;
  core.description = options.description;
  core.poll_interval_ms = options.poll_interval_ms > 0 ? options.poll_interval_ms : 5000;
  core.max_events = options.max_events > 0 ? options.max_events : 50;
  core.next_delay_ms = core.poll_interval_ms;
  core.log = std::move(options.log);
  return SignalsReceiver(std::move(impl));
}

void SignalsReceiver::track(const std::string& local_id, const SamlLogin& login, std::optional<std::chrono::system_clock::time_point> expires) {
  impl->core.index.add(tracked_from(local_id, login, impl->core.subject_attribute, expires));
}

void SignalsReceiver::untrack(const std::string& local_id) { impl->core.index.remove(local_id); }

void SignalsReceiver::on(const std::string& event_type, std::function<void(SignalEvent&)> handler) {
  std::lock_guard<std::mutex> lock(impl->core.mu);
  impl->core.handlers[event_type].push_back(std::move(handler));
}

void SignalsReceiver::start() { impl->core.start(); }
void SignalsReceiver::stop() { impl->core.stop(); }
bool SignalsReceiver::poll_once() { return impl->core.poll_once(); }
std::string SignalsReceiver::stream_id() const { return impl->core.stream_id(); }

std::vector<std::string> SignalsReceiver::sessions_for_person(const std::string& person) const { return impl->core.index.by_person(person); }

}  // namespace iya::saml
