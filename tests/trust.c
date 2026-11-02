// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// idpCa is iya-sts's listener CA trust chain. These tests serve HTTPS from a
// four-certificate chain shaped like iya-sts's (Root, Intermediate, TLS Issuing
// CA, leaf with DNS and IP SANs), presented whole in the handshake and
// published at GET /tls/server-certificate. The service provider fetches its
// identity provider metadata over it (idpMetadata is an https URL).
//
// - The whole chain file is the trust store. The library used to read only the
//   first PEM block (the leaf), so OpenSSL had no self-signed anchor and
//   refused the handshake.
// - The host name is verified: a leaf that chains to the trusted root but does
//   not name the host (DNS or IP SAN) is refused. The library used to set only
//   SNI, so any certificate under the root was accepted for any host.
// - scripts/trust_chain.py writes the whole chain to the file idpCa names, from
//   GET /tls/server-certificate and, when that is missing, from the handshake.

#include "iya_saml.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* kIdp = "https://idp.test/saml2";
static char* sp_key;
static char* sp_cert;
static char* idp_cert;

static int fail(const char* message) {
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

static char* tprintf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list again;
  va_copy(again, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  char* out = malloc((size_t)n + 1);
  vsnprintf(out, (size_t)n + 1, fmt, again);
  va_end(again);
  return out;
}

static char* json_quote(const char* text) {
  size_t cap = strlen(text) * 6 + 3;
  char* out = malloc(cap);
  size_t j = 0;
  out[j++] = '"';
  for (const char* p = text; *p; p++) {
    if (*p == '"' || *p == '\\') {
      out[j++] = '\\';
      out[j++] = *p;
    } else if (*p == '\n') {
      out[j++] = '\\';
      out[j++] = 'n';
    } else if (*p == '\r') {
      out[j++] = '\\';
      out[j++] = 'r';
    } else {
      out[j++] = *p;
    }
  }
  out[j++] = '"';
  out[j] = 0;
  return out;
}

static char* pem_body(const char* pem) {
  char* out = malloc(strlen(pem) + 1);
  size_t j = 0;
  const char* p = strstr(pem, "-----\n");
  p = p ? p + 6 : pem;
  const char* end = strstr(p, "-----END");
  for (; *p && (!end || p < end); p++) {
    if (*p != '\n' && *p != '\r') out[j++] = *p;
  }
  out[j] = 0;
  return out;
}

static EVP_PKEY* rsa_key(void) { return EVP_RSA_gen(2048); }

static int add_ext(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  if (!ext) return 0;
  X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
  return 1;
}

// issuer NULL: self-signed. san NULL: a CA.
static X509* make_cert(const char* cn, EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key, const char* san, long serial) {
  X509* cert = X509_new();
  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
  X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
  X509_set_pubkey(cert, key);
  X509_NAME* name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
  X509* signer = issuer ? issuer : cert;
  X509_set_issuer_name(cert, X509_get_subject_name(signer));
  int ok = 1;
  if (san) {
    ok &= add_ext(cert, signer, NID_basic_constraints, "critical,CA:FALSE");
    ok &= add_ext(cert, signer, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    ok &= add_ext(cert, signer, NID_ext_key_usage, "serverAuth");
    ok &= add_ext(cert, signer, NID_subject_alt_name, san);
  } else {
    ok &= add_ext(cert, signer, NID_basic_constraints, "critical,CA:TRUE");
    ok &= add_ext(cert, signer, NID_key_usage, "critical,keyCertSign,cRLSign");
  }
  ok &= add_ext(cert, signer, NID_subject_key_identifier, "hash");
  if (!ok || !X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256())) {
    X509_free(cert);
    return NULL;
  }
  return cert;
}

static char* pem_of(X509* cert) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, cert);
  char* data = NULL;
  long n = BIO_get_mem_data(bio, &data);
  char* out = malloc((size_t)n + 1);
  memcpy(out, data, (size_t)n);
  out[n] = 0;
  BIO_free(bio);
  return out;
}

typedef struct Chain {
  EVP_PKEY *root_key, *mid_key, *issuing_key, *leaf_key;
  X509 *root, *mid, *issuing, *leaf;
  char* pem;  // leaf, TLS Issuing CA, Intermediate, Root: what iya-sts publishes
  char* root_pem;
  char* leaf_pem;
  char* cas_pem;  // TLS Issuing CA, Intermediate, Root without the leaf
} Chain;

static Chain* make_chain(const char* san) {
  Chain* c = calloc(1, sizeof *c);
  c->root_key = rsa_key();
  c->mid_key = rsa_key();
  c->issuing_key = rsa_key();
  c->leaf_key = rsa_key();
  if (!c->root_key || !c->mid_key || !c->issuing_key || !c->leaf_key) return NULL;
  c->root = make_cert("sts Root CA", c->root_key, NULL, NULL, NULL, 1);
  c->mid = make_cert("sts Intermediate CA", c->mid_key, c->root, c->root_key, NULL, 2);
  c->issuing = make_cert("sts TLS Issuing CA", c->issuing_key, c->mid, c->mid_key, NULL, 3);
  c->leaf = make_cert("sts", c->leaf_key, c->issuing, c->issuing_key, san, 4);
  if (!c->root || !c->mid || !c->issuing || !c->leaf) return NULL;
  c->leaf_pem = pem_of(c->leaf);
  char* issuing = pem_of(c->issuing);
  char* mid = pem_of(c->mid);
  c->root_pem = pem_of(c->root);
  c->pem = tprintf("%s%s%s%s", c->leaf_pem, issuing, mid, c->root_pem);
  c->cas_pem = tprintf("%s%s%s", issuing, mid, c->root_pem);
  free(issuing);
  free(mid);
  return c;
}

typedef struct TlsServer {
  SSL_CTX* ctx;
  int fd;
  int port;
  int publish;  // answer GET /tls/server-certificate
  char* chain_pem;
  char* metadata;
  volatile int stop;
  pthread_t thread;
} TlsServer;

static void serve_one(TlsServer* s, int fd) {
  struct timeval tv = {5, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  SSL* ssl = SSL_new(s->ctx);
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) == 1) {
    char buf[8192];
    int got = 0;
    while (got < (int)sizeof buf - 1) {
      int n = SSL_read(ssl, buf + got, (int)sizeof buf - 1 - got);
      if (n <= 0) break;
      got += n;
      buf[got] = 0;
      if (strstr(buf, "\r\n\r\n")) break;
    }
    buf[got] = 0;
    int status = 404;
    const char* type = "text/plain";
    const char* body = "not found";
    if (strncmp(buf, "GET /tls/server-certificate ", 28) == 0 && s->publish) {
      status = 200;
      body = s->chain_pem;
    } else if (strncmp(buf, "GET /metadata ", 14) == 0) {
      status = 200;
      type = "application/samlmetadata+xml";
      body = s->metadata;
    }
    char* out = tprintf("HTTP/1.1 %d X\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", status, type, strlen(body), body);
    SSL_write(ssl, out, (int)strlen(out));
    free(out);
    SSL_shutdown(ssl);
  }
  SSL_free(ssl);
  ERR_clear_error();
  close(fd);
}

static void* serve_loop(void* arg) {
  TlsServer* s = arg;
  while (!s->stop) {
    struct pollfd pfd = {s->fd, POLLIN, 0};
    if (poll(&pfd, 1, 100) <= 0) continue;
    int fd = accept(s->fd, NULL, NULL);
    if (fd < 0) continue;
    serve_one(s, fd);
  }
  return NULL;
}

// leaf: the certificate the server presents; extra: the certificates after it in the handshake.
static TlsServer* tls_serve_as(X509* leaf, EVP_PKEY* leaf_key, X509** extra, int extra_count, const char* published, int publish, const char* metadata) {
  TlsServer* s = calloc(1, sizeof *s);
  s->ctx = SSL_CTX_new(TLS_server_method());
  if (SSL_CTX_use_certificate(s->ctx, leaf) != 1 || SSL_CTX_use_PrivateKey(s->ctx, leaf_key) != 1) return NULL;
  for (int i = 0; i < extra_count; i++) SSL_CTX_add1_chain_cert(s->ctx, extra[i]);
  s->publish = publish;
  s->chain_pem = (char*)published;
  s->metadata = strdup(metadata ? metadata : "");
  s->fd = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(s->fd, (struct sockaddr*)&addr, sizeof addr) != 0 || listen(s->fd, 16) != 0) return NULL;
  socklen_t len = sizeof addr;
  getsockname(s->fd, (struct sockaddr*)&addr, &len);
  s->port = ntohs(addr.sin_port);
  pthread_create(&s->thread, NULL, serve_loop, s);
  return s;
}

// The whole chain in the handshake, root included, as iya-sts presents it.
static TlsServer* tls_serve(Chain* c, int publish, const char* metadata) {
  X509* extra[3] = {c->issuing, c->mid, c->root};
  return tls_serve_as(c->leaf, c->leaf_key, extra, 3, c->pem, publish, metadata);
}

static void tls_close(TlsServer* s) {
  s->stop = 1;
  pthread_join(s->thread, NULL);
  close(s->fd);
  SSL_CTX_free(s->ctx);
  free(s->metadata);
  free(s);
}

static char* write_temp(const char* text) {
  char path[] = "/tmp/samltrustXXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) return NULL;
  size_t n = strlen(text);
  if (write(fd, text, n) != (ssize_t)n) {
    close(fd);
    return NULL;
  }
  close(fd);
  return strdup(path);
}

static char* idp_metadata(void) {
  char* body = pem_body(idp_cert);
  char* out = tprintf(
      "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"%s\">"
      "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">"
      "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
      "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/saml2/sso\"/>"
      "</md:IDPSSODescriptor></md:EntityDescriptor>",
      kIdp, body);
  free(body);
  return out;
}

// A service provider whose idpMetadata is https://<host>:<port>/metadata and whose idpCa is
// ca_path. Returns 1 when it was created (the metadata was fetched over a verified connection).
static int sp_over_tls(const char* host, int port, const char* ca_path, iya_saml_error* err) {
  char* key = json_quote(sp_key);
  char* cert = json_quote(sp_cert);
  char* ca = json_quote(ca_path);
  char* json = tprintf(
      "{\"entityId\":\"https://sp.test/saml/metadata\",\"acsUrl\":\"https://sp.test/saml/acs\",\"privateKey\":%s,\"certificate\":%s,"
      "\"idpMetadata\":\"https://%s:%d/metadata\",\"idpCa\":%s}",
      key, cert, host, port, ca);
  memset(err, 0, sizeof *err);
  iya_saml_sp* sp = iya_saml_create(json, "", err);
  free(key);
  free(cert);
  free(ca);
  free(json);
  if (!sp) return 0;
  iya_saml_sp_free(sp);
  return 1;
}

static int refused_at_handshake(const iya_saml_error* err) { return strstr(err->message, "tls handshake failed") != NULL; }

static int test_chain_is_trust_store(void) {
  char* metadata = idp_metadata();
  Chain* c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  if (!c) return fail("chain");
  TlsServer* s = tls_serve(c, 1, metadata);
  if (!s) return fail("serve");
  char* chain_path = write_temp(c->pem);
  char* root_path = write_temp(c->root_pem);
  char* leaf_path = write_temp(c->leaf_pem);
  Chain* other = make_chain("DNS:localhost,IP:127.0.0.1");
  if (!other) return fail("other chain");
  char* other_path = write_temp(other->pem);
  iya_saml_error err;
  int rc = 0;
  // The whole chain file: every block is an anchor, so the path ends at the Root.
  if (!sp_over_tls("localhost", s->port, chain_path, &err)) rc = fail(err.message);
  else if (!sp_over_tls("127.0.0.1", s->port, chain_path, &err)) rc = fail(err.message);
  // The root alone is enough too.
  else if (!sp_over_tls("localhost", s->port, root_path, &err)) rc = fail(err.message);
  // The leaf alone is not a self-signed anchor: refused.
  else if (sp_over_tls("localhost", s->port, leaf_path, &err)) rc = fail("the leaf alone was accepted as a trust anchor");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  // A chain to some other root is refused.
  else if (sp_over_tls("localhost", s->port, other_path, &err)) rc = fail("another root's chain was accepted");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  tls_close(s);
  unlink(chain_path);
  unlink(root_path);
  unlink(leaf_path);
  unlink(other_path);
  free(metadata);
  return rc;
}

static int test_forged_leaf_is_refused(void) {
  // A server presents its own self-issued leaf for localhost followed by the
  // real (public) CA certificates. Nothing in the file is that leaf, and it does
  // not chain to the Root: refused. Matching ANY presented certificate against
  // ANY certificate in the file would accept it.
  char* metadata = idp_metadata();
  Chain* real = make_chain("DNS:localhost,IP:127.0.0.1");
  if (!real) return fail("chain");
  EVP_PKEY* forged_key = rsa_key();
  X509* forged = make_cert("sts", forged_key, NULL, NULL, "DNS:localhost,IP:127.0.0.1", 99);
  if (!forged) return fail("forged");
  X509* extra[3] = {real->issuing, real->mid, real->root};
  TlsServer* s = tls_serve_as(forged, forged_key, extra, 3, real->pem, 1, metadata);
  if (!s) return fail("serve");
  char* chain_path = write_temp(real->pem);
  char* cas_path = write_temp(real->cas_pem);
  iya_saml_error err;
  int rc = 0;
  if (sp_over_tls("localhost", s->port, chain_path, &err)) rc = fail("a forged leaf followed by the real CA certificates was accepted");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  else if (sp_over_tls("127.0.0.1", s->port, cas_path, &err)) rc = fail("a forged leaf was accepted against the CA certificates");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  tls_close(s);
  unlink(chain_path);
  unlink(cas_path);
  free(metadata);
  return rc;
}

static int test_host_name_is_checked(void) {
  char* metadata = idp_metadata();
  int rc = 0;
  iya_saml_error err;
  // The Root alone as the trust file, so this checks the name and nothing else.
  // The right chain, the wrong name: the leaf names only sts.example.com.
  Chain* c = make_chain("DNS:sts.example.com");
  if (!c) return fail("chain");
  TlsServer* s = tls_serve(c, 1, metadata);
  char* root_path = write_temp(c->root_pem);
  if (sp_over_tls("localhost", s->port, root_path, &err)) rc = fail("localhost was accepted on a certificate for sts.example.com");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  else if (sp_over_tls("127.0.0.1", s->port, root_path, &err)) rc = fail("127.0.0.1 was accepted without an IP SAN");
  else if (!refused_at_handshake(&err)) rc = fail(err.message);
  tls_close(s);
  unlink(root_path);
  if (rc) return rc;
  // A DNS SAN of 127.0.0.1 is not an IP SAN; an IP literal is matched against IP SANs only.
  Chain* dns_ip = make_chain("DNS:127.0.0.1,DNS:localhost");
  if (!dns_ip) return fail("chain");
  s = tls_serve(dns_ip, 1, metadata);
  char* dns_ip_path = write_temp(dns_ip->root_pem);
  if (sp_over_tls("127.0.0.1", s->port, dns_ip_path, &err)) rc = fail("127.0.0.1 was accepted on a DNS SAN");
  else if (!sp_over_tls("localhost", s->port, dns_ip_path, &err)) rc = fail(err.message);
  tls_close(s);
  unlink(dns_ip_path);
  if (rc) return rc;
  // The right name and the IP SAN are accepted, as on iya-sts's listener certificate.
  Chain* good = make_chain("DNS:localhost,DNS:sts,DNS:sts-mock,DNS:sts.example.com,IP:127.0.0.1");
  if (!good) return fail("chain");
  s = tls_serve(good, 1, metadata);
  char* good_path = write_temp(good->pem);
  if (!sp_over_tls("localhost", s->port, good_path, &err)) rc = fail(err.message);
  else if (!sp_over_tls("127.0.0.1", s->port, good_path, &err)) rc = fail(err.message);
  tls_close(s);
  unlink(good_path);
  free(metadata);
  return rc;
}

static int run_python(const char* script, char* const* args) {
  pid_t pid = fork();
  if (pid == 0) {
    char* argv[16];
    int i = 0;
    argv[i++] = "python3";
    argv[i++] = "-c";
    argv[i++] = (char*)script;
    for (int j = 0; args[j] && i < 15; j++) argv[i++] = args[j];
    argv[i] = NULL;
    execvp("python3", argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int test_configure_writes_the_whole_chain(void) {
  char* metadata = idp_metadata();
  Chain* c = make_chain("DNS:localhost,DNS:sts,IP:127.0.0.1");
  if (!c) return fail("chain");
  TlsServer* published = tls_serve(c, 1, metadata);
  TlsServer* handshake = tls_serve(c, 0, metadata);
  char dir[] = "/tmp/samltrustdirXXXXXX";
  if (!mkdtemp(dir)) return fail("mkdtemp");
  char* config = tprintf("%s/saml.json", dir);
  FILE* f = fopen(config, "w");
  fputs("{\"entityId\":\"http://localhost:3000/saml/metadata\",\"acsUrl\":\"http://localhost:3000/saml/acs\",\"privateKey\":\"file:generated/sp.key\","
        "\"certificate\":\"file:generated/sp.crt\",\"idpMetadata\":\"file:generated/idp-metadata.xml\",\"idpCa\":\"file:generated/idp-ca.pem\"}\n",
        f);
  fclose(f);
  char* want = write_temp(c->pem);
  char* published_url = tprintf("https://127.0.0.1:%d", published->port);
  char* handshake_url = tprintf("https://localhost:%d", handshake->port);
  char* args[] = {"scripts", config, want, published_url, handshake_url, NULL};
  // The configure script's own path to the file, then the published chain through the
  // command the install script shares, then the handshake fallback.
  int ok = run_python(
      "import importlib.util, sys, os, subprocess\n"
      "sys.path.insert(0, sys.argv[1])\n"
      "import trust_chain\n"
      "spec = importlib.util.spec_from_file_location('configure_iya_sts', os.path.join(sys.argv[1], 'configure_iya_sts.py'))\n"
      "mod = importlib.util.module_from_spec(spec)\n"
      "spec.loader.exec_module(mod)\n"
      "config, want, published, handshake = sys.argv[2:]\n"
      "want = open(want).read()\n"
      "dest = os.path.join(os.path.dirname(config), 'generated', 'idp-ca.pem')\n"
      "assert mod.files_of(config).idp_ca == dest, mod.files_of(config).idp_ca\n"
      "assert trust_chain.trust_path('file:generated/idp-ca.pem', os.path.dirname(config)) == dest\n"
      "out = subprocess.run([sys.executable, os.path.join(sys.argv[1], 'trust_chain.py'), '--config', config, '--idp', published],\n"
      "                     capture_output=True, text=True, check=True).stdout\n"
      "assert 'sts Root CA' in out and 'sha256 ' in out and dest in out, out\n"
      "assert open(dest).read() == want, 'the published chain was not written whole'\n"
      "assert open(dest).read().count('BEGIN CERTIFICATE') == 4\n"
      "os.remove(dest)\n"
      "saved = trust_chain.save_trust_chain(handshake, dest)\n"
      "assert saved['count'] == 4, saved['count']\n"
      "assert open(dest).read() == want, 'the handshake chain was not written whole'\n"
      "assert 'CN=sts Root CA' in saved['anchor'].subject.rfc4514_string()\n",
      args);
  int rc = ok ? 0 : fail("trust_chain.py");
  // The file the script wrote is what the library trusts.
  char* dest = tprintf("%s/generated/idp-ca.pem", dir);
  iya_saml_error err;
  if (!rc && !sp_over_tls("localhost", published->port, dest, &err)) rc = fail(err.message);
  tls_close(published);
  tls_close(handshake);
  unlink(dest);
  unlink(want);
  unlink(config);
  char* gen = tprintf("%s/generated", dir);
  rmdir(gen);
  rmdir(dir);
  free(gen);
  free(dest);
  free(config);
  free(published_url);
  free(handshake_url);
  free(metadata);
  return rc;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "test name required\n");
    return 2;
  }
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  char* idp_key = NULL;
  if (iya_saml_create_key_pair("sp.test", 30, 2048, &sp_key, &sp_cert, &err) != 0) return fail(err.message);
  if (iya_saml_create_key_pair("idp.test", 30, 2048, &idp_key, &idp_cert, &err) != 0) return fail(err.message);
  const char* name = argv[1];
  if (strcmp(name, "TestIdpCaChainIsTheTrustStore") == 0) return test_chain_is_trust_store();
  if (strcmp(name, "TestAForgedLeafBeforeTheRealCaIsRefused") == 0) return test_forged_leaf_is_refused();
  if (strcmp(name, "TestHostNameIsChecked") == 0) return test_host_name_is_checked();
  if (strcmp(name, "TestConfigureWritesTheWholeChain") == 0) return test_configure_writes_the_whole_chain();
  fprintf(stderr, "unknown test %s\n", name);
  return 2;
}
