// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>

namespace iya::saml {
namespace {

struct SslInit {
  SslInit() { OPENSSL_init_ssl(0, nullptr); }
};

SslInit ssl_init;

int64_t now_ms() {
  timespec ts {};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

void set_deadline_opts(int fd, int64_t deadline) {
  int64_t left = deadline - now_ms();
  if (left < 1) left = 1;
  timeval tv {};
  tv.tv_sec = static_cast<time_t>(left / 1000);
  tv.tv_usec = static_cast<suseconds_t>((left % 1000) * 1000);
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

bool timed_out(int64_t deadline) { return now_ms() >= deadline; }

bool is_ip_literal(const std::string& host) {
  in_addr v4 {};
  in6_addr v6 {};
  return inet_pton(AF_INET, host.c_str(), &v4) == 1 || inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

// Every certificate in a PEM text, in order.
std::vector<X509*> pem_certs(const std::string& pem) {
  std::vector<X509*> out;
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return out;
  for (;;) {
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    out.push_back(cert);
  }
  BIO_free(bio);
  ERR_clear_error();
  return out;
}

struct Url {
  bool https = false;
  std::string host;
  std::string port;
  std::string path;
};

Url parse_url(const std::string& raw) {
  Url url;
  std::string rest;
  if (starts_with(raw, "https://")) {
    url.https = true;
    rest = raw.substr(8);
    url.port = "443";
  } else if (starts_with(raw, "http://")) {
    rest = raw.substr(7);
    url.port = "80";
  } else {
    throw Failure("binding", raw + " is not an http(s) URL");
  }
  auto slash = rest.find('/');
  std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  url.path = slash == std::string::npos ? "/" : rest.substr(slash);
  if (authority.empty()) throw Failure("binding", raw + " is not an http(s) URL");
  if (authority.front() == '[') {
    auto end = authority.find(']');
    if (end == std::string::npos) throw Failure("binding", raw + " is not an http(s) URL");
    url.host = authority.substr(1, end - 1);
    if (end + 1 < authority.size() && authority[end + 1] == ':') url.port = authority.substr(end + 2);
  } else {
    auto colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      url.host = authority.substr(0, colon);
      url.port = authority.substr(colon + 1);
    } else {
      url.host = authority;
    }
  }
  return url;
}

struct Socket {
  int fd = -1;
  ~Socket() {
    if (fd >= 0) close(fd);
  }
};

struct SslHold {
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;
  ~SslHold() {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
  }
};

int connect_host(const Url& url, int64_t deadline, const std::string& raw, const std::string& code) {
  addrinfo hints {};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* info = nullptr;
  int rc = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &info);
  if (rc != 0) throw Failure(code, raw + ": " + gai_strerror(rc));
  int fd = -1;
  std::string last = "connection failed";
  for (addrinfo* it = info; it; it = it->ai_next) {
    if (timed_out(deadline)) break;
    fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd < 0) continue;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int cr = ::connect(fd, it->ai_addr, it->ai_addrlen);
    if (cr != 0 && errno != EINPROGRESS) {
      last = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    int64_t left = deadline - now_ms();
    if (left < 1) left = 1;
    timeval tv {};
    tv.tv_sec = static_cast<time_t>(left / 1000);
    tv.tv_usec = static_cast<suseconds_t>((left % 1000) * 1000);
    rc = select(fd + 1, nullptr, &fds, nullptr, &tv);
    int err = 0;
    socklen_t len = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (rc > 0 && err == 0) {
      fcntl(fd, F_SETFL, flags);
      break;
    }
    last = err ? std::strerror(err) : "timed out";
    close(fd);
    fd = -1;
  }
  freeaddrinfo(info);
  if (fd < 0) {
    if (timed_out(deadline) || last.find("timed out") != std::string::npos) throw Failure(code, raw + " did not answer within 15 s");
    throw Failure(code, raw + ": " + last);
  }
  return fd;
}

void write_all(int fd, SSL* ssl, const std::string& data, int64_t deadline, const std::string& raw, const std::string& code) {
  size_t off = 0;
  while (off < data.size()) {
    if (timed_out(deadline)) throw Failure(code, raw + " did not answer within 15 s");
    set_deadline_opts(fd, deadline);
    int n = 0;
    if (ssl) {
      n = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
      if (n <= 0) {
        int serr = SSL_get_error(ssl, n);
        if (serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE) continue;
        throw Failure(code, raw + ": tls write failed");
      }
    } else {
      n = static_cast<int>(::send(fd, data.data() + off, data.size() - off, 0));
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
          if (timed_out(deadline)) throw Failure(code, raw + " did not answer within 15 s");
          continue;
        }
        throw Failure(code, raw + ": " + std::strerror(errno));
      }
    }
    off += static_cast<size_t>(n);
  }
}

std::string read_some(int fd, SSL* ssl, int64_t deadline, const std::string& raw, const std::string& code, bool& closed) {
  set_deadline_opts(fd, deadline);
  char buf[8192];
  int n = 0;
  if (ssl) {
    n = SSL_read(ssl, buf, sizeof buf);
    if (n <= 0) {
      int serr = SSL_get_error(ssl, n);
      if (serr == SSL_ERROR_ZERO_RETURN || serr == SSL_ERROR_SYSCALL) {
        closed = true;
        return "";
      }
      if (serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE) return "";
      if (timed_out(deadline)) throw Failure(code, raw + " did not answer within 15 s");
      throw Failure(code, raw + ": tls read failed");
    }
  } else {
    n = static_cast<int>(::recv(fd, buf, sizeof buf, 0));
    if (n == 0) {
      closed = true;
      return "";
    }
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        if (timed_out(deadline)) throw Failure(code, raw + " did not answer within 15 s");
        return "";
      }
      throw Failure(code, raw + ": " + std::strerror(errno));
    }
  }
  return std::string(buf, static_cast<size_t>(n));
}

std::string header_value(const std::string& headers, const std::string& name) {
  std::string lower_name = lower_copy(name);
  size_t i = 0;
  while (i < headers.size()) {
    auto end = headers.find("\r\n", i);
    if (end == std::string::npos) end = headers.size();
    std::string line = headers.substr(i, end - i);
    auto colon = line.find(':');
    if (colon != std::string::npos && lower_copy(trim_copy(line.substr(0, colon))) == lower_name) return trim_copy(line.substr(colon + 1));
    if (end == headers.size()) break;
    i = end + 2;
  }
  return "";
}

std::string decode_chunked(const std::string& body, const std::string& raw, const std::string& code) {
  std::string out;
  size_t i = 0;
  while (i < body.size()) {
    auto line = body.find("\r\n", i);
    if (line == std::string::npos) throw Failure(code, raw + ": incomplete chunk");
    int size = static_cast<int>(std::strtol(body.substr(i, line - i).c_str(), nullptr, 16));
    i = line + 2;
    if (size == 0) break;
    if (i + static_cast<size_t>(size) > body.size()) throw Failure(code, raw + ": incomplete chunk");
    out.append(body, i, static_cast<size_t>(size));
    i += static_cast<size_t>(size);
    if (i + 1 < body.size() && body[i] == '\r') i += 2;
  }
  return out;
}

}  // namespace

HttpResult http_send(const std::string& raw, const std::string& method, const std::vector<std::pair<std::string, std::string>>& headers, const std::string& body,
                     const TlsOpt* tls, const std::string& code) {
  if (!(starts_with(raw, "https://") || starts_with(raw, "http://"))) throw Failure(code, raw + " is not an http(s) URL");
  Url url = parse_url(raw);
  const int64_t deadline = now_ms() + 15000;
  Socket socket;
  socket.fd = connect_host(url, deadline, raw, code);
  SslHold secure;
  SSL* ssl = nullptr;
  if (url.https) {
    secure.ctx = SSL_CTX_new(TLS_client_method());
    if (!secure.ctx) throw Failure(code, raw + ": tls failed");
    SSL_CTX_set_min_proto_version(secure.ctx, TLS1_2_VERSION);
    if (tls && !tls->ca.empty()) {
      // idpCa is iya-sts's listener CA trust chain: leaf, TLS Issuing CA,
      // Intermediate and Root. Every PEM block is a trust anchor. Reading only
      // the first one (the leaf) leaves OpenSSL without the self-signed root,
      // and it refuses the handshake ("self-signed certificate in certificate chain").
      std::vector<X509*> anchors = pem_certs(tls->ca);
      if (anchors.empty()) throw Failure(code, raw + ": the CA certificate cannot be read");
      X509_STORE* store = SSL_CTX_get_cert_store(secure.ctx);
      for (X509* ca : anchors) {
        X509_STORE_add_cert(store, ca);
        X509_free(ca);
      }
      ERR_clear_error();
    } else {
      SSL_CTX_set_default_verify_paths(secure.ctx);
    }
    SSL_CTX_set_verify(secure.ctx, SSL_VERIFY_PEER, nullptr);
    if (tls && !tls->cert.empty() && !tls->key.empty()) {
      BIO* cbio = BIO_new_mem_buf(tls->cert.data(), static_cast<int>(tls->cert.size()));
      X509* cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
      BIO_free(cbio);
      BIO* kbio = BIO_new_mem_buf(tls->key.data(), static_cast<int>(tls->key.size()));
      EVP_PKEY* key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
      BIO_free(kbio);
      if (!cert || !key || SSL_CTX_use_certificate(secure.ctx, cert) != 1 || SSL_CTX_use_PrivateKey(secure.ctx, key) != 1) {
        X509_free(cert);
        EVP_PKEY_free(key);
        throw Failure(code, raw + ": client certificate rejected");
      }
      X509_free(cert);
      EVP_PKEY_free(key);
    }
    secure.ssl = SSL_new(secure.ctx);
    SSL_set_fd(secure.ssl, socket.fd);
    // The certificate must name the host the URL names: a DNS name against a
    // DNS SAN, an IP literal against an IP SAN. A chain to a trusted root is not
    // enough on its own. RFC 6066 sends no server name for an IP literal.
    if (is_ip_literal(url.host)) {
      if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(secure.ssl), url.host.c_str()) != 1) throw Failure(code, raw + ": tls failed");
    } else {
      SSL_set_hostflags(secure.ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
      if (SSL_set1_host(secure.ssl, url.host.c_str()) != 1) throw Failure(code, raw + ": tls failed");
      SSL_set_tlsext_host_name(secure.ssl, url.host.c_str());
    }
    if (SSL_connect(secure.ssl) != 1) throw Failure(code, raw + ": tls handshake failed");
    ssl = secure.ssl;
  }
  std::string host_header = url.host;
  if (!((url.https && url.port == "443") || (!url.https && url.port == "80"))) host_header += ":" + url.port;
  std::string request = method + " " + url.path + " HTTP/1.1\r\nHost: " + host_header + "\r\nConnection: close\r\n";
  bool has_length = false;
  bool has_type = false;
  for (const auto& header : headers) {
    if (lower_copy(header.first) == "content-length") has_length = true;
    if (lower_copy(header.first) == "content-type") has_type = true;
    request += header.first + ": " + header.second + "\r\n";
  }
  bool send_body = method != "GET" && method != "HEAD";
  if (send_body && !has_length) request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  if (send_body && !body.empty() && !has_type) request += "Content-Type: application/octet-stream\r\n";
  request += "\r\n";
  if (send_body) request += body;
  write_all(socket.fd, ssl, request, deadline, raw, code);
  std::string incoming;
  bool closed = false;
  const size_t max_bytes = 2 * 1024 * 1024;
  while (!closed) {
    if (timed_out(deadline)) throw Failure(code, raw + " did not answer within 15 s");
    std::string chunk = read_some(socket.fd, ssl, deadline, raw, code, closed);
    incoming += chunk;
    if (incoming.size() > max_bytes + 4096) throw Failure(code, raw + " answered more than " + std::to_string(max_bytes) + " bytes");
    auto header_end = incoming.find("\r\n\r\n");
    if (header_end == std::string::npos) continue;
    std::string header_text = incoming.substr(0, header_end);
    std::string length_text = header_value(header_text, "content-length");
    bool chunked = lower_copy(header_value(header_text, "transfer-encoding")).find("chunked") != std::string::npos;
    if (!length_text.empty()) {
      size_t need = static_cast<size_t>(std::strtoul(length_text.c_str(), nullptr, 10));
      if (need > max_bytes) throw Failure(code, raw + " answered more than " + std::to_string(max_bytes) + " bytes");
      if (incoming.size() >= header_end + 4 + need) break;
    } else if (!chunked && closed) {
      break;
    }
  }
  auto header_end = incoming.find("\r\n\r\n");
  if (header_end == std::string::npos) throw Failure(code, raw + ": incomplete response");
  std::string header_text = incoming.substr(0, header_end);
  std::string payload = incoming.substr(header_end + 4);
  auto line_end = header_text.find("\r\n");
  std::string status_line = line_end == std::string::npos ? header_text : header_text.substr(0, line_end);
  int status = 0;
  auto sp1 = status_line.find(' ');
  if (sp1 != std::string::npos) status = std::atoi(status_line.c_str() + sp1 + 1);
  if (lower_copy(header_value(header_text, "transfer-encoding")).find("chunked") != std::string::npos) payload = decode_chunked(payload, raw, code);
  else {
    std::string length_text = header_value(header_text, "content-length");
    if (!length_text.empty()) {
      size_t need = static_cast<size_t>(std::strtoul(length_text.c_str(), nullptr, 10));
      if (payload.size() > need) payload.resize(need);
    }
  }
  if (payload.size() > max_bytes) throw Failure(code, raw + " answered more than " + std::to_string(max_bytes) + " bytes");
  HttpResult result;
  result.status = status;
  result.content_type = header_value(header_text, "content-type");
  result.body = std::move(payload);
  return result;
}

}  // namespace iya::saml
