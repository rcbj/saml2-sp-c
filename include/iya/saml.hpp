// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace iya::saml {

// Protocol failures. what() is the message. C wrappers log it once.
class Failure : public std::runtime_error {
 public:
  std::string kind;
  std::string status_code;
  std::string status_subcode;
  std::string status_message;

  Failure(std::string kind, std::string message);
  static Failure status_error(std::string message, std::string code, std::string sub, std::string text);
};

struct LoginOptions {
  std::optional<std::string> relay_state;
  bool force_authn = false;
  bool passive = false;
  std::optional<std::string> subject_hint;
  std::optional<std::string> subject_hint_format;
  std::string request_binding;
  std::string response_binding;
  std::string nonce;
};

struct LoginRequest {
  std::string id;
  std::string binding;
  std::string response_binding;
  std::string url;
  std::string xml;
  std::string html;
  std::map<std::string, std::string> fields;
};

struct SamlLogin {
  std::string name_id;
  std::string name_id_format;
  std::string name_qualifier;
  std::string sp_name_qualifier;
  std::string session_index;
  std::optional<std::chrono::system_clock::time_point> session_not_on_or_after;
  std::chrono::system_clock::time_point authn_instant{};
  std::string authn_context_class_ref;
  std::map<std::string, std::vector<std::string>> attributes;
  std::map<std::string, std::string> attribute_friendly_names;
  std::string issuer;
  std::optional<std::string> in_response_to;
  std::optional<std::string> relay_state;
  std::string binding;
  bool encrypted = false;
  std::string response_id;
  std::string assertion_id;
};

struct KeyPair {
  std::string private_key_pem;
  std::string certificate_pem;
  std::string fingerprint_sha256;
  std::string valid_to;
};

struct KeyDestination {
  std::string key_path;
  std::string cert_path;
  std::string common_name;
};

struct IdpDescription {
  std::string entity_id;
  std::string sso;
  std::vector<std::string> artifact_services;
};

class ServiceProvider {
 public:
  static ServiceProvider create(const std::string& config_json, const std::string& base_dir);
  static ServiceProvider from_file(const std::string& path, const std::map<std::string, std::string>& overrides = {});

  ServiceProvider(ServiceProvider&&) noexcept;
  ServiceProvider& operator=(ServiceProvider&&) noexcept;
  ~ServiceProvider();
  ServiceProvider(const ServiceProvider&) = delete;
  ServiceProvider& operator=(const ServiceProvider&) = delete;

  LoginRequest login(const LoginOptions& options);
  // body is null-equivalent when empty and the method is not POST. A leading '{' is a JSON object of strings.
  SamlLogin acs(const std::string& method, const std::string& raw_url, const std::string& body,
                const std::vector<std::string>& request_ids);

  std::string metadata() const;
  const std::string& entity_id() const;
  const std::string& acs_url() const;
  const std::string& request_binding() const;
  const std::string& response_binding() const;
  bool want_assertions_signed() const;
  bool want_assertions_encrypted() const;
  bool allow_unsolicited() const;
  std::int64_t clock_skew_ms() const;
  bool has_signals() const;
  std::optional<bool> signals() const;
  const std::string& idp_entity_id() const;
  const std::string* idp_sso(const std::string& binding) const;
  int idp_certificate_count() const;
  const std::string& certificate_pem() const;
  const std::string& private_key_pem() const;
  const std::string& idp_ca() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl;
  explicit ServiceProvider(std::unique_ptr<Impl> impl);
};

KeyPair create_key_pair(const std::string& common_name, int days, int bits);
KeyDestination key_destination(const std::string& config_path, const std::string& key, const std::string& cert,
                               const std::string& common_name);
std::string metadata_for_config(const std::string& path, const std::string& entity_id, const std::string& acs_url);
IdpDescription describe_idp(const std::string& metadata_xml);

std::vector<std::string> caep_events();
std::vector<std::string> risc_events();
const char* event_uri(const char* name);

struct SignalEvent {
  std::string type;
  std::string jti;
  bool ended = false;
  std::vector<std::string> sessions;
  std::map<std::string, std::string> subject;
  std::string payload_json;
};

struct ReceiverOptions {
  std::string transmitter;
  std::function<void(const std::vector<std::string>&, SignalEvent&)> on_end_sessions;
  std::string tls_ca;
  std::string tls_cert;
  std::string tls_key;
  std::string description;
  int poll_interval_ms = 0;
  int max_events = 0;
  // level is "info", "warn", or "error". Empty prints the message.
  std::function<void(const std::string& level, const std::string& message)> log;
};

class SignalsReceiver {
 public:
  static SignalsReceiver create(ReceiverOptions options);
  SignalsReceiver(SignalsReceiver&&) noexcept;
  SignalsReceiver& operator=(SignalsReceiver&&) noexcept;
  ~SignalsReceiver();
  SignalsReceiver(const SignalsReceiver&) = delete;
  SignalsReceiver& operator=(const SignalsReceiver&) = delete;

  void track(const std::string& local_id, const SamlLogin& login,
             std::optional<std::chrono::system_clock::time_point> expires = std::nullopt);
  void untrack(const std::string& local_id);
  void on(const std::string& event_type, std::function<void(SignalEvent&)> handler);
  void start();
  void stop();
  bool poll_once();
  std::string stream_id() const;
  std::vector<std::string> sessions_for_person(const std::string& person) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl;
  explicit SignalsReceiver(std::unique_ptr<Impl> impl);
};

}  // namespace iya::saml
