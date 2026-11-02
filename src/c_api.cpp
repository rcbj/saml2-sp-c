// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_saml.h"
#include "internal.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace {

char* dup_str(const std::string& value) {
  char* out = static_cast<char*>(std::malloc(value.size() + 1));
  if (!out) return nullptr;
  std::memcpy(out, value.data(), value.size());
  out[value.size()] = '\0';
  return out;
}

void fill_error(iya_saml_error* err, const iya::saml::Failure& failure) {
  std::fprintf(stderr, "%s\n", failure.what());
  if (!err) return;
  std::memset(err, 0, sizeof *err);
  err->failed = 1;
  std::snprintf(err->code, sizeof err->code, "%s", failure.kind.c_str());
  std::snprintf(err->message, sizeof err->message, "%s", failure.what());
  std::snprintf(err->status_code, sizeof err->status_code, "%s", failure.status_code.c_str());
  std::snprintf(err->status_subcode, sizeof err->status_subcode, "%s", failure.status_subcode.c_str());
  std::snprintf(err->status_message, sizeof err->status_message, "%s", failure.status_message.c_str());
}

int fail_unknown(iya_saml_error* err, const std::exception& ex) {
  iya::saml::Failure failure("error", ex.what());
  fill_error(err, failure);
  return -1;
}

struct SpBox {
  iya::saml::ServiceProvider provider;
  explicit SpBox(iya::saml::ServiceProvider value) : provider(std::move(value)) {}
};

struct ReceiverBox {
  iya_saml_end_fn on_end = nullptr;
  void* user = nullptr;
  std::unique_ptr<iya::saml::SignalsReceiver> receiver;
};

void fill_event(const iya::saml::SignalEvent& event, iya_saml_event* out, std::vector<const char*>& sessions) {
  sessions.clear();
  for (const std::string& id : event.sessions) sessions.push_back(id.c_str());
  std::memset(out, 0, sizeof *out);
  out->type = event.type.c_str();
  out->jti = event.jti.c_str();
  out->ended = event.ended ? 1 : 0;
  out->sessions = sessions.empty() ? nullptr : sessions.data();
  out->session_count = static_cast<int>(sessions.size());
  auto person = event.subject.find("person");
  auto email = event.subject.find("email");
  auto idp = event.subject.find("idp_session");
  out->person = person == event.subject.end() ? "" : person->second.c_str();
  out->email = email == event.subject.end() ? "" : email->second.c_str();
  out->idp_session = idp == event.subject.end() ? "" : idp->second.c_str();
}

const char* or_empty(const char* value) { return value ? value : ""; }

}  // namespace

extern "C" {

iya_saml_sp* iya_saml_create(const char* config_json, const char* base_dir, iya_saml_error* err) {
  try {
    auto provider = iya::saml::ServiceProvider::create(or_empty(config_json), or_empty(base_dir));
    return reinterpret_cast<iya_saml_sp*>(new SpBox(std::move(provider)));
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return nullptr;
  } catch (const std::exception& ex) {
    fail_unknown(err, ex);
    return nullptr;
  }
}

void iya_saml_sp_free(iya_saml_sp* sp) { delete reinterpret_cast<SpBox*>(sp); }

const char* iya_saml_entity_id(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.entity_id().c_str(); }
const char* iya_saml_acs_url(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.acs_url().c_str(); }
const char* iya_saml_request_binding(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.request_binding().c_str(); }
const char* iya_saml_response_binding(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.response_binding().c_str(); }
int iya_saml_want_assertions_signed(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.want_assertions_signed() ? 1 : 0; }
int iya_saml_want_assertions_encrypted(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.want_assertions_encrypted() ? 1 : 0; }
int iya_saml_allow_unsolicited(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.allow_unsolicited() ? 1 : 0; }
long long iya_saml_clock_skew_ms(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.clock_skew_ms(); }
int iya_saml_has_signals(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.has_signals() ? 1 : 0; }
int iya_saml_signals_value(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.signals().value_or(true) ? 1 : 0; }
const char* iya_saml_idp_entity_id(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.idp_entity_id().c_str(); }

const char* iya_saml_idp_sso(const iya_saml_sp* sp, const char* binding) {
  const std::string* value = reinterpret_cast<const SpBox*>(sp)->provider.idp_sso(or_empty(binding));
  return value ? value->c_str() : nullptr;
}

int iya_saml_idp_certificate_count(const iya_saml_sp* sp) { return reinterpret_cast<const SpBox*>(sp)->provider.idp_certificate_count(); }

int iya_saml_metadata(const iya_saml_sp* sp, char** out, iya_saml_error* err) {
  try {
    if (out) *out = dup_str(reinterpret_cast<const SpBox*>(sp)->provider.metadata());
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_login(iya_saml_sp* sp, const iya_saml_login_options* options, iya_saml_login_request* out, iya_saml_error* err) {
  try {
    iya::saml::LoginOptions request;
    if (options) {
      if (options->relay_state) request.relay_state = options->relay_state;
      request.force_authn = options->force_authn != 0;
      request.passive = options->passive != 0;
      if (options->subject_hint) request.subject_hint = options->subject_hint;
      if (options->subject_hint_format) request.subject_hint_format = options->subject_hint_format;
      if (options->request_binding) request.request_binding = options->request_binding;
      if (options->response_binding) request.response_binding = options->response_binding;
      if (options->nonce) request.nonce = options->nonce;
    }
    iya::saml::LoginRequest made = reinterpret_cast<SpBox*>(sp)->provider.login(request);
    if (out) {
      std::memset(out, 0, sizeof *out);
      out->id = dup_str(made.id);
      out->binding = dup_str(made.binding);
      out->response_binding = dup_str(made.response_binding);
      out->url = dup_str(made.url);
      out->xml = dup_str(made.xml);
      out->html = dup_str(made.html);
      auto saml = made.fields.find("SAMLRequest");
      if (saml != made.fields.end()) out->saml_request = dup_str(saml->second);
      auto relay = made.fields.find("RelayState");
      if (relay != made.fields.end()) out->relay_state = dup_str(relay->second);
    }
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

void iya_saml_login_request_free(iya_saml_login_request* request) {
  if (!request) return;
  std::free(request->id);
  std::free(request->binding);
  std::free(request->response_binding);
  std::free(request->url);
  std::free(request->xml);
  std::free(request->html);
  std::free(request->saml_request);
  std::free(request->relay_state);
  std::memset(request, 0, sizeof *request);
}

int iya_saml_acs(iya_saml_sp* sp, const char* method, const char* raw_url, const char* body, const char* const* request_ids, int request_id_count,
                 iya_saml_acs_result* out, iya_saml_error* err) {
  try {
    std::vector<std::string> ids;
    for (int i = 0; i < request_id_count; i++) ids.emplace_back(request_ids && request_ids[i] ? request_ids[i] : "");
    iya::saml::SamlLogin login = reinterpret_cast<SpBox*>(sp)->provider.acs(or_empty(method), or_empty(raw_url), body ? body : "", ids);
    if (out) {
      std::memset(out, 0, sizeof *out);
      out->name_id = dup_str(login.name_id);
      out->name_id_format = dup_str(login.name_id_format);
      out->session_index = dup_str(login.session_index);
      out->authn_context = dup_str(login.authn_context_class_ref);
      out->binding = dup_str(login.binding);
      if (login.relay_state) out->relay_state = dup_str(*login.relay_state);
      if (login.in_response_to) out->in_response_to = dup_str(*login.in_response_to);
      out->encrypted = login.encrypted ? 1 : 0;
      out->assertion_id = dup_str(login.assertion_id);
      out->issuer = dup_str(login.issuer);
      int count = 0;
      for (const auto& item : login.attributes) count += static_cast<int>(item.second.size());
      out->attr_count = count;
      if (count > 0) {
        out->attr_name = static_cast<char**>(std::calloc(static_cast<size_t>(count), sizeof(char*)));
        out->attr_values = static_cast<char**>(std::calloc(static_cast<size_t>(count), sizeof(char*)));
        out->attr_friendly = static_cast<char**>(std::calloc(static_cast<size_t>(count), sizeof(char*)));
        int index = 0;
        for (const auto& item : login.attributes) {
          std::string friendly;
          auto found = login.attribute_friendly_names.find(item.first);
          if (found != login.attribute_friendly_names.end()) friendly = found->second;
          for (const std::string& value : item.second) {
            out->attr_name[index] = dup_str(item.first);
            out->attr_values[index] = dup_str(value);
            out->attr_friendly[index] = dup_str(friendly);
            index++;
          }
        }
      }
    }
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

void iya_saml_login_free(iya_saml_acs_result* login) {
  if (!login) return;
  std::free(login->name_id);
  std::free(login->name_id_format);
  std::free(login->session_index);
  std::free(login->authn_context);
  std::free(login->binding);
  std::free(login->relay_state);
  std::free(login->in_response_to);
  std::free(login->assertion_id);
  std::free(login->issuer);
  for (int i = 0; i < login->attr_count; i++) {
    if (login->attr_name) std::free(login->attr_name[i]);
    if (login->attr_values) std::free(login->attr_values[i]);
    if (login->attr_friendly) std::free(login->attr_friendly[i]);
  }
  std::free(login->attr_name);
  std::free(login->attr_values);
  std::free(login->attr_friendly);
  std::memset(login, 0, sizeof *login);
}

int iya_saml_create_key_pair(const char* common_name, int days, int bits, char** key_pem, char** cert_pem, iya_saml_error* err) {
  try {
    iya::saml::KeyPair pair = iya::saml::create_key_pair(or_empty(common_name), days, bits);
    if (key_pem) *key_pem = dup_str(pair.private_key_pem);
    if (cert_pem) *cert_pem = dup_str(pair.certificate_pem);
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_sign_xml(const char* xml, const char* element_id, const char* key_pem, const char* cert_pem, char** out, iya_saml_error* err) {
  try {
    iya::saml::OwnedKey key = iya::saml::load_private_key(or_empty(key_pem));
    iya::saml::OwnedCert cert = iya::saml::load_certificate(or_empty(cert_pem));
    std::string signed_xml = iya::saml::sign_enveloped(or_empty(xml), or_empty(element_id), key.key, cert.cert);
    if (out) *out = dup_str(signed_xml);
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_signature_verifies(const char* xml, const char* cert_pem, iya_saml_error* err) {
  try {
    iya::saml::XmlDoc doc = iya::saml::parse_xml(or_empty(xml), "the message");
    iya::saml::OwnedCert cert = iya::saml::load_certificate(or_empty(cert_pem));
    std::string signed_form = iya::saml::verify_signed(doc.root(), {cert.cert}, "the message");
    if (signed_form.empty()) {
      fill_error(err, iya::saml::Failure("signature", "the signature does not verify"));
      return -1;
    }
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_xml_well_formed(const char* xml) {
  try {
    iya::saml::XmlDoc doc = iya::saml::parse_xml(or_empty(xml), "the document");
    return doc.root() ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

int iya_saml_read_artifact_resolve(const char* xml, const char* cert_pem, char* id, size_t id_cap, char* artifact, size_t artifact_cap, int* signature_ok) {
  try {
    iya::saml::ArtifactResolveView view = iya::saml::read_artifact_resolve(or_empty(xml), or_empty(cert_pem));
    if (id && id_cap) {
      std::snprintf(id, id_cap, "%s", view.id.c_str());
    }
    if (artifact && artifact_cap) std::snprintf(artifact, artifact_cap, "%s", view.artifact.c_str());
    if (signature_ok) *signature_ok = view.signature_ok ? 1 : 0;
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(nullptr, failure);
    return -1;
  } catch (const std::exception& ex) {
    fill_error(nullptr, iya::saml::Failure("xml", ex.what()));
    return -1;
  }
}

int iya_saml_caep_event_count(void) { return static_cast<int>(iya::saml::caep_events().size()); }
int iya_saml_risc_event_count(void) { return static_cast<int>(iya::saml::risc_events().size()); }
const char* iya_saml_event_uri(const char* name) { return iya::saml::event_uri(name); }

int iya_saml_subject(const char* sub_json, const char* issuer, char* person, size_t person_cap, char* email, size_t email_cap, char* idp_session,
                     size_t idp_cap, iya_saml_error* err) {
  try {
    iya::saml::Json parsed = iya::saml::parse_json(or_empty(sub_json));
    auto subject = iya::saml::subject_of(parsed, or_empty(issuer));
    if (person && person_cap) std::snprintf(person, person_cap, "%s", subject["person"].c_str());
    if (email && email_cap) std::snprintf(email, email_cap, "%s", subject["email"].c_str());
    if (idp_session && idp_cap) std::snprintf(idp_session, idp_cap, "%s", subject["idp_session"].c_str());
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_verify_jws(const char* token, const char* keys_json, char** payload_json, iya_saml_error* err) {
  try {
    iya::saml::Json parsed = iya::saml::parse_json(or_empty(keys_json));
    std::vector<iya::saml::Json> keys;
    if (parsed.type == iya::saml::Json::Type::Array) keys = parsed.items;
    else if (parsed.type == iya::saml::Json::Type::Object && parsed.find("keys") && parsed.find("keys")->type == iya::saml::Json::Type::Array) {
      keys = parsed.find("keys")->items;
    }
    iya::saml::Json header;
    iya::saml::Json payload;
    std::string raw = iya::saml::verify_compact_jws(or_empty(token), keys, header, payload);
    if (payload_json) *payload_json = dup_str(raw);
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

iya_saml_receiver* iya_saml_receiver_new(const char* transmitter, int poll_interval_ms, iya_saml_end_fn on_end, void* user, iya_saml_log_fn log, void* log_user,
                                        iya_saml_error* err) {
  try {
    auto box = std::make_unique<ReceiverBox>();
    box->on_end = on_end;
    box->user = user;
    iya::saml::ReceiverOptions options;
    options.transmitter = or_empty(transmitter);
    options.poll_interval_ms = poll_interval_ms;
    options.on_end_sessions = [raw = box.get()](const std::vector<std::string>& ids, iya::saml::SignalEvent& event) {
      if (!raw->on_end) return;
      std::vector<const char*> pointers;
      for (const std::string& id : ids) pointers.push_back(id.c_str());
      iya_saml_event view;
      std::vector<const char*> sessions;
      fill_event(event, &view, sessions);
      char message[1024];
      message[0] = '\0';
      int rc = raw->on_end(pointers.empty() ? nullptr : pointers.data(), static_cast<int>(pointers.size()), &view, raw->user, message, sizeof message);
      if (rc != 0) throw iya::saml::Failure("ssf", message[0] ? message : "onEndSessions failed");
    };
    if (log) {
      options.log = [log, log_user](const std::string& level, const std::string& message) { log(level.c_str(), message.c_str(), log_user); };
    }
    box->receiver = std::make_unique<iya::saml::SignalsReceiver>(iya::saml::SignalsReceiver::create(std::move(options)));
    return reinterpret_cast<iya_saml_receiver*>(box.release());
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return nullptr;
  } catch (const std::exception& ex) {
    fail_unknown(err, ex);
    return nullptr;
  }
}

void iya_saml_receiver_free(iya_saml_receiver* receiver) { delete reinterpret_cast<ReceiverBox*>(receiver); }

void iya_saml_receiver_on(iya_saml_receiver* receiver, const char* event_type, iya_saml_handler_fn fn, void* user) {
  if (!receiver || !fn) return;
  auto* box = reinterpret_cast<ReceiverBox*>(receiver);
  std::string type = or_empty(event_type);
  box->receiver->on(type, [fn, user](iya::saml::SignalEvent& event) {
    iya_saml_event view;
    std::vector<const char*> sessions;
    fill_event(event, &view, sessions);
    char message[1024];
    message[0] = '\0';
    int rc = fn(&view, user, message, sizeof message);
    if (rc != 0) throw iya::saml::Failure("ssf", message[0] ? message : "handler failed");
  });
}

void iya_saml_receiver_track(iya_saml_receiver* receiver, const char* local_id, const char* person, const char* email, const char* idp_session) {
  if (!receiver) return;
  iya::saml::SamlLogin login;
  login.name_id = or_empty(person);
  login.session_index = or_empty(idp_session);
  if (person && person[0]) login.attributes[iya::saml::kDefaultSubject] = {person};
  if (email && email[0]) login.attributes["urn:oid:0.9.2342.19200300.100.1.3"] = {email};
  reinterpret_cast<ReceiverBox*>(receiver)->receiver->track(or_empty(local_id), login);
}

int iya_saml_receiver_start(iya_saml_receiver* receiver, iya_saml_error* err) {
  try {
    reinterpret_cast<ReceiverBox*>(receiver)->receiver->start();
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

void iya_saml_receiver_stop(iya_saml_receiver* receiver) {
  if (!receiver) return;
  try {
    reinterpret_cast<ReceiverBox*>(receiver)->receiver->stop();
  } catch (const iya::saml::Failure& failure) {
    fill_error(nullptr, failure);
  } catch (const std::exception& ex) {
    fill_error(nullptr, iya::saml::Failure("ssf", ex.what()));
  }
}

int iya_saml_receiver_poll(iya_saml_receiver* receiver, int* more, iya_saml_error* err) {
  try {
    bool again = reinterpret_cast<ReceiverBox*>(receiver)->receiver->poll_once();
    if (more) *more = again ? 1 : 0;
    return 0;
  } catch (const iya::saml::Failure& failure) {
    fill_error(err, failure);
    return -1;
  } catch (const std::exception& ex) {
    return fail_unknown(err, ex);
  }
}

int iya_saml_receiver_stream_id(const iya_saml_receiver* receiver, char* buf, size_t cap) {
  std::string id = reinterpret_cast<const ReceiverBox*>(receiver)->receiver->stream_id();
  if (buf && cap) std::snprintf(buf, cap, "%s", id.c_str());
  return static_cast<int>(id.size());
}

int iya_saml_receiver_sessions_for_person(const iya_saml_receiver* receiver, const char* person, char* buf, size_t cap) {
  auto ids = reinterpret_cast<const ReceiverBox*>(receiver)->receiver->sessions_for_person(or_empty(person));
  std::string joined;
  for (size_t i = 0; i < ids.size(); i++) {
    if (i) joined.push_back(',');
    joined += ids[i];
  }
  if (buf && cap) std::snprintf(buf, cap, "%s", joined.c_str());
  return static_cast<int>(joined.size());
}

void iya_saml_string_free(char* value) { std::free(value); }

}  // extern "C"
