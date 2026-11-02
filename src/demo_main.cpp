// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::atomic<int> g_stop{0};

void on_signal(int) { g_stop = 1; }

int g_port = 3000;
bool g_public_given = false;
std::string g_public_url;
std::string g_config_path;
std::string g_secret;
bool g_secure_cookies = true;
bool g_signals_off = false;
std::string g_ssf_transmitter;
int g_ssf_poll_ms = 0;
std::string g_receiver_state = "not configured (no ssf block in the configuration file)";
std::unique_ptr<iya::saml::ServiceProvider> g_sp;
std::string g_sp_error;
std::once_flag g_sp_once;
std::unique_ptr<iya::saml::SignalsReceiver> g_receiver;
std::thread g_receiver_thread;
std::mutex g_sessions_mu;

struct Held {
  iya::saml::SamlLogin login;
  std::chrono::system_clock::time_point expires;
};

std::map<std::string, Held> g_sessions;

constexpr auto kSession = std::chrono::hours(8);

std::string read_text(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return "";
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

std::string b64url(const std::string& data) {
  std::string out = iya::saml::b64_encode(data);
  for (char& c : out) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

std::string b64url_dec(const std::string& data) {
  std::string padded = data;
  for (char& c : padded) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (padded.size() % 4) padded.push_back('=');
  return iya::saml::b64_decode(padded);
}

std::string random_bytes(int n) {
  std::string out(static_cast<size_t>(n), '\0');
  RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), n);
  return out;
}

std::string html_escape(const std::string& value) {
  std::string out;
  for (char c : value) {
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else out.push_back(c);
  }
  return out;
}

std::string seal(const std::string& json) {
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), g_secret.data(), static_cast<int>(g_secret.size()), reinterpret_cast<const unsigned char*>(json.data()), json.size(), mac, &len);
  return b64url(json) + "." + b64url(std::string(reinterpret_cast<char*>(mac), len));
}

std::string unseal(const std::string& value) {
  auto dot = value.find('.');
  if (dot == std::string::npos) return "";
  std::string raw;
  std::string sig;
  try {
    raw = b64url_dec(value.substr(0, dot));
    sig = b64url_dec(value.substr(dot + 1));
  } catch (...) {
    return "";
  }
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), g_secret.data(), static_cast<int>(g_secret.size()), reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), mac, &len);
  if (sig.size() != len || CRYPTO_memcmp(sig.data(), mac, len) != 0) return "";
  return raw;
}

struct UrlParts {
  std::string scheme;
  std::string host;
  std::string path;
};

UrlParts parse_http_url(const std::string& raw) {
  UrlParts out;
  auto scheme = raw.find("://");
  if (scheme == std::string::npos) return out;
  out.scheme = raw.substr(0, scheme);
  std::string rest = raw.substr(scheme + 3);
  auto slash = rest.find('/');
  out.host = slash == std::string::npos ? rest : rest.substr(0, slash);
  out.path = slash == std::string::npos ? "" : rest.substr(slash);
  return out;
}

std::string host_name(const std::string& host) {
  if (!host.empty() && host.front() == '[') {
    auto end = host.find(']');
    if (end != std::string::npos) return host.substr(1, end - 1);
  }
  auto colon = host.rfind(':');
  if (colon != std::string::npos && host.find(':') == colon) return host.substr(0, colon);
  return host;
}

std::string replace_origin(const std::string& value, const std::string& pub) {
  UrlParts base = parse_http_url(pub);
  UrlParts parsed = parse_http_url(value);
  if (base.scheme.empty() || parsed.scheme.empty()) return value;
  return base.scheme + "://" + base.host + parsed.path;
}

std::string on_port(const std::string& raw, int number) {
  UrlParts parsed = parse_http_url(raw);
  if (parsed.scheme.empty()) return raw;
  std::string host = host_name(parsed.host);
  if (host != "localhost" && host != "127.0.0.1" && host != "::1") return raw;
  std::string next = host.find(':') != std::string::npos ? "[" + host + "]" : host;
  return parsed.scheme + "://" + next + ":" + std::to_string(number) + parsed.path;
}

std::pair<std::string, std::string> endpoints_of(const std::string& entity, const std::string& acs) {
  if (g_public_given && !g_public_url.empty()) return {replace_origin(entity, g_public_url), replace_origin(acs, g_public_url)};
  return {on_port(entity, g_port), on_port(acs, g_port)};
}

iya::saml::Json read_config_json() {
  std::string raw = read_text(g_config_path);
  if (raw.empty()) return {};
  try {
    iya::saml::Json parsed = iya::saml::parse_json(raw);
    if (parsed.type != iya::saml::Json::Type::Object) return {};
    return parsed;
  } catch (...) {
    return {};
  }
}

void configure(int argc, char** argv) {
  if (const char* raw = std::getenv("PORT")) {
    int n = std::atoi(raw);
    if (n < 1 || n > 65535 || std::to_string(n) != raw) throw std::runtime_error("PORT is not a port");
    g_port = n;
  }
  if (const char* pub = std::getenv("PUBLIC_URL")) {
    g_public_url = pub;
    while (!g_public_url.empty() && g_public_url.back() == '/') g_public_url.pop_back();
    g_public_given = true;
  }
  if (const char* path = std::getenv("SAML_CONFIG")) g_config_path = path;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--public-url") {
      if (i + 1 >= argc) throw std::runtime_error("--public-url needs a value");
      g_public_url = argv[++i];
      while (!g_public_url.empty() && g_public_url.back() == '/') g_public_url.pop_back();
      g_public_given = true;
    } else if (arg == "--config") {
      if (i + 1 >= argc) throw std::runtime_error("--config needs a value");
      g_config_path = argv[++i];
    } else {
      throw std::runtime_error("Unknown argument " + arg);
    }
  }
  if (g_public_given && g_public_url.empty()) throw std::runtime_error("--public-url is empty");
  if (g_config_path.empty()) g_config_path = "demo/saml.json";
  g_config_path = fs::absolute(g_config_path).string();
  if (const char* secret = std::getenv("SESSION_SECRET")) g_secret = secret;
  else g_secret = random_bytes(32);
  iya::saml::Json file = read_config_json();
  if (const iya::saml::Json* signals = file.find("signals"); signals && signals->type == iya::saml::Json::Type::Bool && !signals->b) {
    g_signals_off = true;
    g_receiver_state = "not configured (signals are off)";
  }
  if (const iya::saml::Json* ssf = file.find("ssf"); ssf && ssf->type == iya::saml::Json::Type::Object && !g_signals_off) {
    g_ssf_transmitter = ssf->str_or("transmitter");
    if (const iya::saml::Json* n = ssf->find("pollIntervalMs"); n && n->type == iya::saml::Json::Type::Number) g_ssf_poll_ms = static_cast<int>(n->num);
  }
  std::string acs = file.str_or("acsUrl");
  std::string entity = file.str_or("entityId");
  if (!entity.empty() && !acs.empty()) {
    auto replaced = endpoints_of(entity, acs);
    acs = replaced.second;
  } else {
    acs = "http://localhost:" + std::to_string(g_port) + "/";
  }
  UrlParts parsed = parse_http_url(acs);
  std::string host = host_name(parsed.host);
  g_secure_cookies = parsed.scheme == "https" || host == "localhost" || host == "127.0.0.1";
}

void start_receiver(iya::saml::ServiceProvider& sp) {
  if (sp.has_signals() && sp.signals() && !*sp.signals()) {
    g_receiver_state = "not configured (signals are off)";
    return;
  }
  if (g_ssf_transmitter.empty() || g_receiver) return;
  iya::saml::ReceiverOptions options;
  options.transmitter = g_ssf_transmitter;
  options.tls_cert = sp.certificate_pem();
  options.tls_key = sp.private_key_pem();
  if (!sp.idp_ca().empty()) options.tls_ca = sp.idp_ca();
  options.description = "saml2-sp demo (" + sp.entity_id() + ")";
  options.poll_interval_ms = g_ssf_poll_ms;
  options.on_end_sessions = [](const std::vector<std::string>& ids, iya::saml::SignalEvent&) {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    for (const std::string& id : ids) g_sessions.erase(id);
    std::printf("ssf: ended %zu local session(s)\n", ids.size());
    std::fflush(stdout);
  };
  try {
    g_receiver = std::make_unique<iya::saml::SignalsReceiver>(iya::saml::SignalsReceiver::create(std::move(options)));
  } catch (const std::exception& ex) {
    g_receiver_state = std::string("not running: ") + ex.what();
    return;
  }
  iya::saml::SignalsReceiver* built = g_receiver.get();
  g_receiver_thread = std::thread([built] {
    try {
      built->start();
      g_receiver_state = "polling stream " + built->stream_id() + " at " + g_ssf_transmitter;
    } catch (const std::exception& ex) {
      g_receiver_state = std::string("not running: ") + ex.what();
      std::printf("ssf: the receiver did not start: %s\n", ex.what());
      std::fflush(stdout);
    }
  });
}

iya::saml::ServiceProvider* provider() {
  std::call_once(g_sp_once, [] {
    try {
      iya::saml::Json file = read_config_json();
      std::map<std::string, std::string> overrides;
      std::string entity = file.str_or("entityId");
      std::string acs = file.str_or("acsUrl");
      if (!entity.empty() && !acs.empty()) {
        auto replaced = endpoints_of(entity, acs);
        overrides["entityId"] = replaced.first;
        overrides["acsUrl"] = replaced.second;
      }
      g_sp = std::make_unique<iya::saml::ServiceProvider>(iya::saml::ServiceProvider::from_file(g_config_path, overrides));
      start_receiver(*g_sp);
    } catch (const std::exception& ex) {
      g_sp_error = ex.what();
    }
  });
  return g_sp.get();
}

struct Request {
  std::string method;
  std::string path;
  std::string query;
  std::map<std::string, std::string> headers;
  std::string body;
};

std::string header_get(const Request& request, const std::string& name) {
  for (const auto& item : request.headers) {
    if (iya::saml::lower_copy(item.first) == name) return item.second;
  }
  return "";
}

std::map<std::string, std::string> cookies_of(const Request& request) {
  std::map<std::string, std::string> out;
  std::string raw = header_get(request, "cookie");
  size_t i = 0;
  while (i < raw.size()) {
    auto semi = raw.find(';', i);
    if (semi == std::string::npos) semi = raw.size();
    std::string part = iya::saml::trim_copy(raw.substr(i, semi - i));
    auto eq = part.find('=');
    if (eq != std::string::npos) out[part.substr(0, eq)] = part.substr(eq + 1);
    i = semi + 1;
  }
  return out;
}

std::string query_get(const std::string& query, const std::string& key) {
  auto values = iya::saml::query_map(query);
  auto found = values.find(key);
  return found == values.end() ? "" : found->second;
}

std::string cookie_header(const std::string& name, const std::string& value, const std::string& path, int max_age, const std::string& same_site) {
  std::ostringstream out;
  out << name << "=" << value << "; Path=" << path << "; Max-Age=" << max_age << "; HttpOnly";
  if (g_secure_cookies) out << "; Secure";
  out << "; SameSite=" << same_site;
  return out.str();
}

void send_all(int fd, const std::string& data) {
  size_t sent = 0;
  while (sent < data.size()) {
    ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
    if (n <= 0) return;
    sent += static_cast<size_t>(n);
  }
}

void respond(int fd, int status, const std::string& reason, const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body) {
  std::ostringstream out;
  out << "HTTP/1.1 " << status << " " << reason << "\r\n";
  out << "content-length: " << body.size() << "\r\n";
  out << "connection: close\r\n";
  for (const auto& header : headers) out << header.first << ": " << header.second << "\r\n";
  out << "\r\n";
  send_all(fd, out.str());
  send_all(fd, body);
}

void write_page(int fd, const std::string& title, const std::string& body, int status) {
  std::string html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + html_escape(title) +
                     "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body>" + body + "</body></html>";
  respond(fd, status, status == 200 ? "OK" : "Error", {{"content-type", "text/html; charset=utf-8"}}, html);
}

std::string acs_path(iya::saml::ServiceProvider& sp) {
  UrlParts parsed = parse_http_url(sp.acs_url());
  return parsed.path.empty() ? "/" : parsed.path;
}

bool current_session(const std::string& sid, Held* out) {
  if (sid.empty()) return false;
  std::lock_guard<std::mutex> lock(g_sessions_mu);
  auto found = g_sessions.find(sid);
  if (found == g_sessions.end() || std::chrono::system_clock::now() > found->second.expires) {
    if (found != g_sessions.end()) g_sessions.erase(found);
    return false;
  }
  *out = found->second;
  return true;
}

void handle(int fd, const Request& request) {
  if (request.path == "/healthz") {
    respond(fd, 200, "OK", {{"content-type", "text/plain"}}, "ok");
    return;
  }
  if (request.path == "/styles.css" || request.path == "/app.js") {
    std::string file = request.path == "/styles.css" ? "demo/public/styles.css" : "demo/public/app.js";
    std::string body = read_text(file);
    std::string type = request.path == "/styles.css" ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8";
    respond(fd, body.empty() ? 404 : 200, body.empty() ? "Not Found" : "OK", {{"content-type", type}}, body);
    return;
  }
  if (request.path == "/saml/metadata") {
    iya::saml::ServiceProvider* sp = provider();
    if (!sp) {
      respond(fd, 500, "Internal Server Error", {{"content-type", "text/plain"}}, g_sp_error);
      return;
    }
    respond(fd, 200, "OK", {{"content-type", "application/samlmetadata+xml"}}, sp->metadata());
    return;
  }
  if (request.path == "/" && request.method == "GET") {
    std::string problem;
    iya::saml::ServiceProvider* sp = provider();
    if (!sp) problem = "The service provider is not configured yet: " + g_sp_error + ". Run the setup script (python scripts/configure_iya_sts.py).";
    auto cookies = cookies_of(request);
    Held current;
    bool signed_in = current_session(cookies["sid"], &current);
    std::string body = "<h1>SAML service provider</h1>";
    if (!problem.empty() && !signed_in) body += "<p class=\"problem\">" + html_escape(problem) + "</p>";
    body += "<p>Shared Signals: " + html_escape(g_receiver_state) + "</p>";
    if (signed_in) {
      body += "<p>Signed in as <strong>" + html_escape(current.login.name_id) + "</strong> (" + html_escape(current.login.binding) + ").</p>";
      body += "<form method=\"post\" action=\"/logout\"><button type=\"submit\">Log out</button></form>";
    } else if (problem.empty()) {
      body += "<p><a href=\"/login\">Sign in</a></p>";
    }
    write_page(fd, "saml2-sp", body, 200);
    return;
  }
  if (request.path == "/login" && request.method == "GET") {
    iya::saml::ServiceProvider* sp = provider();
    if (!sp) {
      write_page(fd, "Sign-in", "<h1>Sign-in is not available</h1><p class=\"problem\">" + html_escape(g_sp_error) + "</p>", 500);
      return;
    }
    std::string asked = query_get(request.query, "binding");
    iya::saml::LoginOptions options;
    options.relay_state = "/";
    options.nonce = b64url(random_bytes(16));
    if (asked == "post" || asked == "redirect" || asked == "artifact") options.response_binding = asked;
    try {
      iya::saml::LoginRequest made = sp->login(options);
      std::string pending = std::string("{\"ids\":[\"") + made.id + "\"]}";
      std::vector<std::pair<std::string, std::string>> headers{{"set-cookie", cookie_header("saml_pending", seal(pending), acs_path(*sp), 600, "None")}};
      if (made.binding == "redirect") {
        headers.push_back({"referrer-policy", "no-referrer"});
        headers.push_back({"location", made.url});
        respond(fd, 302, "Found", headers, "");
        return;
      }
      UrlParts origin = parse_http_url(made.url);
      headers.push_back({"content-security-policy", "default-src 'none'; script-src 'nonce-" + options.nonce + "'; form-action " + origin.scheme + "://" + origin.host +
                                                         "; frame-ancestors 'none'; base-uri 'none'"});
      headers.push_back({"content-type", "text/html; charset=utf-8"});
      respond(fd, 200, "OK", headers, made.html);
    } catch (const std::exception& ex) {
      write_page(fd, "Sign-in", "<h1>Sign-in failed</h1><p class=\"problem\">" + html_escape(ex.what()) + "</p>", 400);
    }
    return;
  }
  if (request.path == "/saml/acs" && (request.method == "GET" || request.method == "POST")) {
    iya::saml::ServiceProvider* sp = provider();
    if (!sp) {
      write_page(fd, "Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + html_escape(g_sp_error) + "</p>", 400);
      return;
    }
    auto cookies = cookies_of(request);
    std::string pending = unseal(cookies.count("saml_pending") ? cookies["saml_pending"] : "");
    std::vector<std::string> ids;
    try {
      if (!pending.empty()) {
        iya::saml::Json parsed = iya::saml::parse_json(pending);
        if (const iya::saml::Json* list = parsed.find("ids"); list && list->type == iya::saml::Json::Type::Array) {
          for (const iya::saml::Json& item : list->items) {
            if (item.type == iya::saml::Json::Type::String) ids.push_back(item.text);
          }
        }
      }
    } catch (...) {
    }
    std::string raw = request.path;
    if (!request.query.empty()) raw += "?" + request.query;
    try {
      iya::saml::SamlLogin login = sp->acs(request.method, raw, request.method == "POST" ? request.body : "", ids);
      std::string sid = b64url(random_bytes(32));
      auto until = std::chrono::system_clock::now() + kSession;
      if (login.session_not_on_or_after && *login.session_not_on_or_after < until) until = *login.session_not_on_or_after;
      iya::saml::SamlLogin tracked = login;
      {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        g_sessions[sid] = Held{std::move(login), until};
      }
      if (g_receiver) g_receiver->track(sid, tracked, until);
      std::printf("signed in %s by %s (assertion %s)\n", tracked.name_id.c_str(), tracked.binding.c_str(), tracked.assertion_id.c_str());
      std::fflush(stdout);
      int max_age = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(until - std::chrono::system_clock::now()).count());
      if (max_age < 0) max_age = 0;
      respond(fd, 303, "See Other",
              {{"set-cookie", cookie_header("saml_pending", "", acs_path(*sp), 0, "None")},
               {"set-cookie", cookie_header("sid", sid, "/", max_age, "Lax")},
               {"location", "/"}},
              "");
    } catch (const std::exception& ex) {
      respond(fd, 400, "Bad Request",
              {{"set-cookie", cookie_header("saml_pending", "", acs_path(*sp), 0, "None")}, {"content-type", "text/html; charset=utf-8"}},
              "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign-in failed</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><h1>Sign-in failed</h1><p class=\"problem\">" +
                  html_escape(ex.what()) + "</p><p><a href=\"/\">Start again</a></p></body></html>");
    }
    return;
  }
  if (request.path == "/logout" && request.method == "POST") {
    auto cookies = cookies_of(request);
    std::string sid = cookies.count("sid") ? cookies["sid"] : "";
    if (!sid.empty()) {
      std::lock_guard<std::mutex> lock(g_sessions_mu);
      g_sessions.erase(sid);
      if (g_receiver) g_receiver->untrack(sid);
    }
    respond(fd, 303, "See Other", {{"set-cookie", cookie_header("sid", "", "/", 0, "Lax")}, {"location", "/"}}, "");
    return;
  }
  respond(fd, 404, "Not Found", {{"content-type", "text/plain"}}, "not found");
}

std::string read_headers(int fd) {
  std::string data;
  char buf[1024];
  while (data.find("\r\n\r\n") == std::string::npos && data.size() < 65536) {
    ssize_t n = ::recv(fd, buf, sizeof buf, 0);
    if (n <= 0) break;
    data.append(buf, static_cast<size_t>(n));
  }
  return data;
}

void serve(int fd) {
  std::string incoming = read_headers(fd);
  auto split = incoming.find("\r\n\r\n");
  if (split == std::string::npos) return;
  std::string head = incoming.substr(0, split);
  std::string rest = incoming.substr(split + 4);
  std::istringstream lines(head);
  std::string start;
  std::getline(lines, start);
  if (!start.empty() && start.back() == '\r') start.pop_back();
  Request request;
  {
    std::istringstream parts(start);
    std::string target;
    parts >> request.method >> target;
    auto q = target.find('?');
    request.path = q == std::string::npos ? target : target.substr(0, q);
    request.query = q == std::string::npos ? "" : target.substr(q + 1);
  }
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    request.headers[iya::saml::trim_copy(line.substr(0, colon))] = iya::saml::trim_copy(line.substr(colon + 1));
  }
  size_t length = 0;
  try {
    length = static_cast<size_t>(std::stoul(header_get(request, "content-length")));
  } catch (...) {
    length = 0;
  }
  if (length > 512 * 1024) length = 512 * 1024;
  request.body = rest.substr(0, std::min(rest.size(), length));
  while (request.body.size() < length) {
    char buf[4096];
    ssize_t n = ::recv(fd, buf, sizeof buf, 0);
    if (n <= 0) break;
    request.body.append(buf, static_cast<size_t>(n));
  }
  if (request.body.size() > length) request.body.resize(length);
  handle(fd, request);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    configure(argc, argv);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << "\n";
    return 1;
  }
  int server = ::socket(AF_INET, SOCK_STREAM, 0);
  if (server < 0) {
    std::cerr << std::strerror(errno) << "\n";
    return 1;
  }
  int yes = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(g_port));
  if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || listen(server, 64) != 0) {
    std::cerr << std::strerror(errno) << "\n";
    return 1;
  }
  ::signal(SIGINT, on_signal);
  ::signal(SIGTERM, on_signal);
  std::printf("saml2-sp demo on port %d, configuration %s\n", g_port, g_config_path.c_str());
  std::fflush(stdout);
  while (!g_stop) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(server, &fds);
    timeval tv {};
    tv.tv_sec = 1;
    int ready = select(server + 1, &fds, nullptr, nullptr, &tv);
    if (ready <= 0) continue;
    int client = accept(server, nullptr, nullptr);
    if (client < 0) continue;
    serve(client);
    ::close(client);
  }
  if (g_receiver) g_receiver->stop();
  if (g_receiver_thread.joinable()) g_receiver_thread.join();
  ::close(server);
  return 0;
}
