/* SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC */
/* SPDX-License-Identifier: MIT */

#define _GNU_SOURCE

#include "iya_saml.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <zlib.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char* kIdp = "https://idp.test/saml2";
static const char* kSp = "https://sp.test/saml/metadata";
static const char* kAcs = "https://sp.test/saml/acs";
static const char* kSso = "https://idp.test/saml2/sso";
static const char* kRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

static char* sp_key;
static char* sp_cert;
static char* idp_key;
static char* idp_cert;
static EVP_PKEY* sp_pkey;
static EVP_PKEY* idp_pkey;
static EVP_PKEY* tx_key;
static EVP_PKEY* other_key;

static int fail(const char* message) {
  printf("FAIL %s\n", message);
  return 1;
}

static int fail_err(const char* what, const iya_saml_error* err) {
  printf("FAIL %s: %s: %s\n", what, err->code, err->message);
  return 1;
}

static int contains(const char* text, const char* needle) { return text && needle && strstr(text, needle) != NULL; }

static char* dup_str(const char* text) {
  size_t n = strlen(text);
  char* out = malloc(n + 1);
  memcpy(out, text, n + 1);
  return out;
}

static char* b64(const unsigned char* data, size_t len) {
  size_t out_len = 4 * ((len + 2) / 3);
  char* out = malloc(out_len + 1);
  EVP_EncodeBlock((unsigned char*)out, data, (int)len);
  return out;
}

static unsigned char* b64_dec(const char* text, size_t* out_len) {
  size_t n = strlen(text);
  unsigned char* out = malloc(n + 4);
  int len = EVP_DecodeBlock(out, (const unsigned char*)text, (int)n);
  if (len < 0) {
    free(out);
    return NULL;
  }
  while (n > 0 && text[n - 1] == '=') {
    len--;
    n--;
  }
  *out_len = (size_t)len;
  return out;
}

static char* b64url(const unsigned char* data, size_t len) {
  char* text = b64(data, len);
  for (char* p = text; *p; p++) {
    if (*p == '+') *p = '-';
    else if (*p == '/') *p = '_';
  }
  size_t n = strlen(text);
  while (n > 0 && text[n - 1] == '=') text[--n] = '\0';
  return text;
}

static char* json_quote(const char* text) {
  size_t cap = strlen(text) * 2 + 3;
  char* out = malloc(cap);
  size_t j = 0;
  out[j++] = '"';
  for (const unsigned char* p = (const unsigned char*)text; *p; p++) {
    if (j + 8 >= cap) {
      cap *= 2;
      out = realloc(out, cap);
    }
    if (*p == '\\' || *p == '"') {
      out[j++] = '\\';
      out[j++] = (char)*p;
    } else if (*p == '\n') {
      out[j++] = '\\';
      out[j++] = 'n';
    } else if (*p == '\r') {
      out[j++] = '\\';
      out[j++] = 'r';
    } else if (*p < 0x20) {
      j += (size_t)snprintf(out + j, cap - j, "\\u%04x", *p);
    } else out[j++] = (char)*p;
  }
  out[j++] = '"';
  out[j] = '\0';
  return out;
}

static char* uri_escape(const char* text) {
  static const char* hex = "0123456789ABCDEF";
  size_t cap = strlen(text) * 3 + 1;
  char* out = malloc(cap);
  size_t j = 0;
  for (const unsigned char* p = (const unsigned char*)text; *p; p++) {
    if (isalnum(*p) || strchr("-_.!~*'()", *p)) out[j++] = (char)*p;
    else {
      out[j++] = '%';
      out[j++] = hex[*p >> 4];
      out[j++] = hex[*p & 15];
    }
  }
  out[j] = '\0';
  return out;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static char* uri_unescape(const char* text) {
  char* out = malloc(strlen(text) + 1);
  size_t j = 0;
  for (size_t i = 0; text[i]; i++) {
    if (text[i] == '%' && hex_val(text[i + 1]) >= 0 && hex_val(text[i + 2]) >= 0) {
      out[j++] = (char)((hex_val(text[i + 1]) << 4) | hex_val(text[i + 2]));
      i += 2;
    } else if (text[i] == '+') out[j++] = ' ';
    else out[j++] = text[i];
  }
  out[j] = '\0';
  return out;
}

static char* deflate_raw(const char* text, size_t* out_len) {
  z_stream stream;
  memset(&stream, 0, sizeof stream);
  if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return NULL;
  stream.next_in = (Bytef*)text;
  stream.avail_in = (uInt)strlen(text);
  size_t cap = strlen(text) + 64;
  char* out = malloc(cap);
  size_t used = 0;
  int rc = Z_OK;
  while (rc != Z_STREAM_END) {
    if (used + 4096 > cap) {
      cap *= 2;
      out = realloc(out, cap);
    }
    stream.next_out = (Bytef*)out + used;
    stream.avail_out = 4096;
    rc = deflate(&stream, Z_FINISH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
      deflateEnd(&stream);
      free(out);
      return NULL;
    }
    used += 4096 - stream.avail_out;
  }
  deflateEnd(&stream);
  *out_len = used;
  return out;
}

static char* inflate_raw(const unsigned char* data, size_t len) {
  z_stream stream;
  memset(&stream, 0, sizeof stream);
  if (inflateInit2(&stream, -15) != Z_OK) return NULL;
  stream.next_in = (Bytef*)data;
  stream.avail_in = (uInt)len;
  size_t cap = len * 4 + 64;
  char* out = malloc(cap + 1);
  size_t used = 0;
  int rc = Z_OK;
  while (rc != Z_STREAM_END) {
    if (used + 4096 > cap) {
      cap *= 2;
      out = realloc(out, cap + 1);
    }
    stream.next_out = (Bytef*)out + used;
    stream.avail_out = 4096;
    rc = inflate(&stream, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
      inflateEnd(&stream);
      free(out);
      return NULL;
    }
    used += 4096 - stream.avail_out;
  }
  inflateEnd(&stream);
  out[used] = '\0';
  return out;
}

static EVP_PKEY* pem_key(const char* pem) {
  BIO* bio = BIO_new_mem_buf(pem, -1);
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return key;
}

static EVP_PKEY* pem_pub(const char* pem) {
  BIO* bio = BIO_new_mem_buf(pem, -1);
  X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  EVP_PKEY* key = cert ? X509_get_pubkey(cert) : NULL;
  X509_free(cert);
  return key;
}

static char* pem_body(const char* pem) {
  const char* start = strstr(pem, "-----BEGIN CERTIFICATE-----");
  const char* end = strstr(pem, "-----END CERTIFICATE-----");
  if (!start || !end) return dup_str("");
  start += strlen("-----BEGIN CERTIFICATE-----");
  size_t cap = (size_t)(end - start) + 1;
  char* out = malloc(cap);
  size_t j = 0;
  for (const char* p = start; p < end; p++) {
    if (!isspace((unsigned char)*p)) out[j++] = *p;
  }
  out[j] = '\0';
  return out;
}

static char* rsa_sign(EVP_PKEY* key, const char* data) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  size_t len = 0;
  EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
  EVP_DigestSignUpdate(ctx, data, strlen(data));
  EVP_DigestSignFinal(ctx, NULL, &len);
  unsigned char* sig = malloc(len);
  EVP_DigestSignFinal(ctx, sig, &len);
  EVP_MD_CTX_free(ctx);
  char* text = b64(sig, len);
  free(sig);
  return text;
}

static int rsa_verify(EVP_PKEY* key, const char* data, const unsigned char* sig, size_t sig_len) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  int ok = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1 && EVP_DigestVerifyUpdate(ctx, data, strlen(data)) == 1 &&
           EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1;
  EVP_MD_CTX_free(ctx);
  return ok;
}

static char* new_id(void) {
  unsigned char buf[20];
  RAND_bytes(buf, sizeof buf);
  char* out = malloc(41);
  out[0] = '_';
  static const char* hex = "0123456789abcdef";
  for (int i = 0; i < 20; i++) {
    out[1 + i * 2] = hex[buf[i] >> 4];
    out[2 + i * 2] = hex[buf[i] & 15];
  }
  out[41] = '\0';
  return out;
}

static char* iso_off(int ms) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  long long total = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + ms;
  time_t sec = (time_t)(total / 1000);
  int millis = (int)(total % 1000);
  if (millis < 0) {
    millis += 1000;
    sec -= 1;
  }
  struct tm tm;
  gmtime_r(&sec, &tm);
  char* out = malloc(32);
  snprintf(out, 32, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
  return out;
}

static char* idp_metadata(const char* ars) {
  if (!ars || !ars[0]) ars = "https://idp.test/saml2/ars";
  char* body = pem_body(idp_cert);
  size_t cap = strlen(body) + strlen(ars) + 1024;
  char* out = malloc(cap);
  snprintf(out, cap,
           "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"%s\">"
           "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\">"
           "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
           "<md:ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"%s\" index=\"0\" isDefault=\"true\"/>"
           "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"%s\"/>"
           "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"%s\"/>"
           "</md:IDPSSODescriptor></md:EntityDescriptor>",
           kIdp, body, ars, kSso, kSso);
  free(body);
  return out;
}

static char* config_json(const char* extra, const char* ars) {
  char* meta = idp_metadata(ars);
  char* key = json_quote(sp_key);
  char* cert = json_quote(sp_cert);
  char* meta_q = json_quote(meta);
  size_t cap = strlen(key) + strlen(cert) + strlen(meta_q) + (extra ? strlen(extra) : 0) + 512;
  char* out = malloc(cap);
  snprintf(out, cap, "{\"entityId\":\"%s\",\"acsUrl\":\"%s\",\"privateKey\":%s,\"certificate\":%s,\"idpMetadata\":%s%s%s}", kSp, kAcs, key, cert, meta_q,
           extra && extra[0] ? "," : "", extra ? extra : "");
  free(meta);
  free(key);
  free(cert);
  free(meta_q);
  return out;
}

static iya_saml_sp* must_sp(const char* extra, const char* ars, iya_saml_error* err) {
  char* json = config_json(extra, ars);
  iya_saml_sp* sp = iya_saml_create(json, "", err);
  free(json);
  return sp;
}

static int rejects(iya_saml_sp* sp, const char* method, const char* url, const char* body, const char* request_id, const char* code, const char* pattern) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  const char* ids[1] = {request_id};
  int count = request_id && request_id[0] ? 1 : 0;
  int rc = iya_saml_acs(sp, method, url, body, count ? ids : NULL, count, &login, &err);
  iya_saml_login_free(&login);
  if (rc == 0) return fail("expected an error");
  if (strcmp(err.code, code) != 0) {
    printf("FAIL code %s want %s: %s\n", err.code, code, err.message);
    return 1;
  }
  if (pattern && pattern[0] && !contains(err.message, pattern)) {
    printf("FAIL message %s does not match %s\n", err.message, pattern);
    return 1;
  }
  return 0;
}

typedef struct {
  const char* in_response_to;
  const char* name_id;
  const char* audience;
  const char* recipient;
  int expiry_ms;
  int has_expiry;
  const char* issuer;
  const char* extra;
} AssertionOpt;

static char* assertion_xml(AssertionOpt opt, char** id_out) {
  char* id = new_id();
  char* now = iso_off(0);
  char* before = iso_off(-5000);
  char* expiry = iso_off(opt.has_expiry ? opt.expiry_ms : 300000);
  char* authn = iso_off(-1000);
  const char* name = opt.name_id && opt.name_id[0] ? opt.name_id : "alice-1234";
  const char* audience = opt.audience && opt.audience[0] ? opt.audience : kSp;
  const char* recipient = opt.recipient && opt.recipient[0] ? opt.recipient : kAcs;
  const char* issuer = opt.issuer && opt.issuer[0] ? opt.issuer : kIdp;
  const char* extra = opt.extra ? opt.extra : "";
  char irt[128] = "";
  if (opt.in_response_to && opt.in_response_to[0]) snprintf(irt, sizeof irt, " InResponseTo=\"%s\"", opt.in_response_to);
  size_t cap = strlen(name) + strlen(audience) + strlen(recipient) + strlen(issuer) + strlen(extra) + 2048;
  char* xml = malloc(cap);
  snprintf(xml, cap,
           "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\">"
           "<saml:Issuer>%s</saml:Issuer>"
           "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">%s</saml:NameID>"
           "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
           "<saml:SubjectConfirmationData Recipient=\"%s\" NotOnOrAfter=\"%s\"%s/>"
           "</saml:SubjectConfirmation></saml:Subject>"
           "<saml:Conditions NotBefore=\"%s\" NotOnOrAfter=\"%s\">"
           "<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
           "<saml:AuthnStatement AuthnInstant=\"%s\" SessionIndex=\"_session1\"><saml:AuthnContext>"
           "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
           "</saml:AuthnContext></saml:AuthnStatement>"
           "<saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\" FriendlyName=\"mail\">"
           "<saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>"
           "<saml:Attribute Name=\"groups\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>"
           "%s</saml:AttributeStatement></saml:Assertion>",
           id, now, issuer, name, recipient, expiry, irt, before, expiry, audience, authn, extra);
  free(now);
  free(before);
  free(expiry);
  free(authn);
  if (id_out) *id_out = id;
  else free(id);
  return xml;
}

static char* sign_xml(const char* xml, const char* id, const char* key, const char* cert) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  char* out = NULL;
  if (iya_saml_sign_xml(xml, id, key ? key : idp_key, cert ? cert : idp_cert, &out, &err) != 0) {
    printf("FAIL sign: %s\n", err.message);
    return NULL;
  }
  return out;
}

static char* signed_assertion(AssertionOpt opt, char** id_out) {
  char* id = NULL;
  char* xml = assertion_xml(opt, &id);
  char* signed_xml = sign_xml(xml, id, NULL, NULL);
  free(xml);
  if (id_out) *id_out = id;
  else free(id);
  return signed_xml;
}

typedef struct {
  const char* in_response_to;
  int sign;
  const char* assertion;
  int has_assertion;
  const char* status;
  const char* destination;
  int has_destination;
  int omit_destination;
  const char* issuer;
} ResponseOpt;

static char* response_xml(ResponseOpt opt) {
  char* id = new_id();
  char* now = iso_off(0);
  const char* status = opt.status && opt.status[0] ? opt.status : "urn:oasis:names:tc:SAML:2.0:status:Success";
  const char* issuer = opt.issuer && opt.issuer[0] ? opt.issuer : kIdp;
  char* owned = NULL;
  const char* assertion = opt.assertion;
  if (!opt.has_assertion) {
    if (strstr(status, "Success")) {
      AssertionOpt made = {0};
      made.in_response_to = opt.in_response_to;
      owned = signed_assertion(made, NULL);
      assertion = owned;
    } else assertion = "";
  }
  if (!assertion) assertion = "";
  char irt[128] = "";
  char dest[256] = "";
  if (opt.in_response_to && opt.in_response_to[0]) snprintf(irt, sizeof irt, " InResponseTo=\"%s\"", opt.in_response_to);
  if (!opt.omit_destination) {
    const char* value = opt.has_destination ? opt.destination : kAcs;
    snprintf(dest, sizeof dest, " Destination=\"%s\"", value);
  }
  size_t cap = strlen(assertion) + 1024;
  char* xml = malloc(cap);
  snprintf(xml, cap,
           "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\"%s%s>"
           "<saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"%s\"/></samlp:Status>%s</samlp:Response>",
           id, now, dest, irt, issuer, status, assertion);
  free(id);
  free(now);
  free(owned);
  if (opt.sign) {
    const char* response_id = strstr(xml, "ID=\"");
    char rid[64];
    if (response_id) {
      response_id += 4;
      size_t n = 0;
      while (response_id[n] && response_id[n] != '"' && n + 1 < sizeof rid) {
        rid[n] = response_id[n];
        n++;
      }
      rid[n] = '\0';
      char* signed_xml = sign_xml(xml, rid, NULL, NULL);
      free(xml);
      return signed_xml;
    }
  }
  return xml;
}

static char* post_body(const char* xml, const char* relay) {
  char* encoded = b64((const unsigned char*)xml, strlen(xml));
  char* quoted = json_quote(encoded);
  char* relay_q = relay ? json_quote(relay) : NULL;
  size_t cap = strlen(quoted) + (relay_q ? strlen(relay_q) : 0) + 64;
  char* out = malloc(cap);
  if (relay_q) snprintf(out, cap, "{\"SAMLResponse\":%s,\"RelayState\":%s}", quoted, relay_q);
  else snprintf(out, cap, "{\"SAMLResponse\":%s}", quoted);
  free(encoded);
  free(quoted);
  free(relay_q);
  return out;
}

static int attr_has(const iya_saml_acs_result* login, const char* name, const char* value) {
  for (int i = 0; i < login->attr_count; i++) {
    if (strcmp(login->attr_name[i], name) == 0 && strcmp(login->attr_values[i], value) == 0) return 1;
  }
  return 0;
}

static const char* attr_friendly(const iya_saml_acs_result* login, const char* name) {
  for (int i = 0; i < login->attr_count; i++) {
    if (strcmp(login->attr_name[i], name) == 0) return login->attr_friendly[i];
  }
  return "";
}

static char* oaep_wrap(EVP_PKEY* pub, const unsigned char* key, size_t key_len, const EVP_MD* md) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, NULL);
  EVP_PKEY_encrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
  size_t len = 0;
  EVP_PKEY_encrypt(ctx, NULL, &len, key, key_len);
  unsigned char* out = malloc(len);
  EVP_PKEY_encrypt(ctx, out, &len, key, key_len);
  EVP_PKEY_CTX_free(ctx);
  char* text = b64(out, len);
  free(out);
  return text;
}

static char* encrypt_assertion(const char* assertion, const char* cipher_name, const char* transport, const char* wrapper) {
  if (!cipher_name || !cipher_name[0]) cipher_name = "aes-256-gcm";
  if (!transport || !transport[0]) transport = "mgf1p";
  if (!wrapper || !wrapper[0]) wrapper = "EncryptedAssertion";
  int gcm = strcmp(cipher_name, "aes-256-gcm") == 0;
  int key_len = gcm ? 32 : 16;
  unsigned char key[32];
  RAND_bytes(key, key_len);
  unsigned char iv[16];
  int iv_len = gcm ? 12 : 16;
  RAND_bytes(iv, iv_len);
  unsigned char* blob = NULL;
  size_t blob_len = 0;
  const char* alg = gcm ? "http://www.w3.org/2009/xmlenc11#aes256-gcm" : "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (gcm) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    int out_len = (int)strlen(assertion) + 32;
    unsigned char* cipher = malloc((size_t)out_len);
    int written = 0;
    EVP_EncryptUpdate(ctx, cipher, &written, (const unsigned char*)assertion, (int)strlen(assertion));
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, cipher + written, &final_len);
    written += final_len;
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    blob_len = 12 + (size_t)written + 16;
    blob = malloc(blob_len);
    memcpy(blob, iv, 12);
    memcpy(blob + 12, cipher, (size_t)written);
    memcpy(blob + 12 + written, tag, 16);
    free(cipher);
  } else {
    size_t plain_len = strlen(assertion);
    int pad = 16 - (int)(plain_len % 16);
    size_t padded = plain_len + (size_t)pad;
    unsigned char* plain = malloc(padded);
    memcpy(plain, assertion, plain_len);
    memset(plain + plain_len, pad, (size_t)pad);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    unsigned char* cipher = malloc(padded);
    int written = 0;
    EVP_EncryptUpdate(ctx, cipher, &written, plain, (int)padded);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, cipher + written, &final_len);
    blob_len = 16 + (size_t)written + (size_t)final_len;
    blob = malloc(blob_len);
    memcpy(blob, iv, 16);
    memcpy(blob + 16, cipher, (size_t)written + (size_t)final_len);
    free(plain);
    free(cipher);
  }
  EVP_CIPHER_CTX_free(ctx);
  EVP_PKEY* pub = pem_pub(sp_cert);
  char* wrapped = oaep_wrap(pub, key, (size_t)key_len, strcmp(transport, "mgf1p") == 0 ? EVP_sha1() : EVP_sha256());
  EVP_PKEY_free(pub);
  char* cipher_b64 = b64(blob, blob_len);
  free(blob);
  const char* key_method = "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>";
  const char* oaep256 =
      "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\">"
      "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
      "<xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/>"
      "</xenc:EncryptionMethod>";
  size_t cap = strlen(wrapped) + strlen(cipher_b64) + strlen(wrapper) * 2 + 1024;
  char* out = malloc(cap);
  snprintf(out, cap,
           "<saml:%s xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
           "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
           "<xenc:EncryptionMethod Algorithm=\"%s\"/>"
           "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>%s"
           "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
           "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData>"
           "</xenc:EncryptedData></saml:%s>",
           wrapper, alg, strcmp(transport, "mgf1p") == 0 ? key_method : oaep256, wrapped, cipher_b64, wrapper);
  free(wrapped);
  free(cipher_b64);
  return out;
}

static char* redirect_response_query(const char* xml, const char* relay, EVP_PKEY* key) {
  size_t deflated_len = 0;
  char* deflated = deflate_raw(xml, &deflated_len);
  char* encoded = b64((const unsigned char*)deflated, deflated_len);
  free(deflated);
  char* enc_esc = uri_escape(encoded);
  free(encoded);
  char* relay_esc = relay && relay[0] ? uri_escape(relay) : NULL;
  char* alg_esc = uri_escape(kRsaSha256);
  size_t cap = strlen(enc_esc) + (relay_esc ? strlen(relay_esc) : 0) + strlen(alg_esc) + 128;
  char* signed_text = malloc(cap);
  if (relay_esc) snprintf(signed_text, cap, "SAMLResponse=%s&RelayState=%s&SigAlg=%s", enc_esc, relay_esc, alg_esc);
  else snprintf(signed_text, cap, "SAMLResponse=%s&SigAlg=%s", enc_esc, alg_esc);
  char* sig = rsa_sign(key ? key : idp_pkey, signed_text);
  char* sig_esc = uri_escape(sig);
  char* out = malloc(strlen(signed_text) + strlen(sig_esc) + 16);
  sprintf(out, "%s&Signature=%s", signed_text, sig_esc);
  free(enc_esc);
  free(relay_esc);
  free(alg_esc);
  free(signed_text);
  free(sig);
  free(sig_esc);
  return out;
}

static char* artifact_for(const char* entity) {
  if (!entity || !entity[0]) entity = kIdp;
  unsigned char out[44];
  memset(out, 0, sizeof out);
  out[1] = 4;
  unsigned char sum[20];
  unsigned int len = 20;
  EVP_Digest(entity, strlen(entity), sum, &len, EVP_sha1(), NULL);
  memcpy(out + 4, sum, 20);
  RAND_bytes(out + 24, 20);
  return b64(out, sizeof out);
}

typedef struct {
  int fd;
  pthread_t thread;
  char url[128];
  pthread_mutex_t mu;
  char* store_art;
  char* store_xml;
  char resolved[512];
  int stop;
} Ars;

static void http_write(int fd, int status, const char* type, const char* body) {
  char header[256];
  int n = snprintf(header, sizeof header, "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status, type, strlen(body));
  if (status != 200) n = snprintf(header, sizeof header, "HTTP/1.1 %d X\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status, type, strlen(body));
  send(fd, header, (size_t)n, MSG_NOSIGNAL);
  send(fd, body, strlen(body), MSG_NOSIGNAL);
}

static char* read_http(int fd, char** method, char** path, char** body) {
  char* data = malloc(1);
  size_t len = 0;
  size_t cap = 1;
  while (len < 4 || !strstr(data, "\r\n\r\n")) {
    if (len + 1024 > cap) {
      cap = cap * 2 + 1024;
      data = realloc(data, cap);
    }
    ssize_t n = recv(fd, data + len, 1024, 0);
    if (n <= 0) break;
    len += (size_t)n;
    data[len] = '\0';
    if (len > 2 * 1024 * 1024) break;
  }
  char* split = strstr(data, "\r\n\r\n");
  *method = dup_str("");
  *path = dup_str("/");
  *body = dup_str("");
  if (!split) {
    free(data);
    return data;
  }
  *split = '\0';
  char* line_end = strstr(data, "\r\n");
  if (line_end) *line_end = '\0';
  char* sp1 = strchr(data, ' ');
  char* sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
  if (sp1 && sp2) {
    *sp1 = '\0';
    *sp2 = '\0';
    free(*method);
    free(*path);
    *method = dup_str(data);
    *path = dup_str(sp1 + 1);
  }
  char* headers = line_end ? line_end + 2 : data;
  size_t content_length = 0;
  char* cl = strcasestr(headers, "Content-Length:");
  if (cl) content_length = (size_t)strtoul(cl + 15, NULL, 10);
  char* rest = split + 4;
  size_t have = strlen(rest);
  while (have < content_length) {
    size_t total = (size_t)(rest - data) + have;
    if (total + 4096 > cap) {
      size_t offset = (size_t)(rest - data);
      cap = total + 4096;
      data = realloc(data, cap);
      rest = data + offset;
    }
    ssize_t n = recv(fd, rest + have, 4096, 0);
    if (n <= 0) break;
    have += (size_t)n;
    rest[have] = '\0';
  }
  if (have > content_length) have = content_length;
  free(*body);
  *body = malloc(have + 1);
  memcpy(*body, rest, have);
  (*body)[have] = '\0';
  return data;
}

static void* ars_thread(void* arg) {
  Ars* ars = arg;
  while (!ars->stop) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(ars->fd, &fds);
    struct timeval tv = {0, 200000};
    if (select(ars->fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
    int client = accept(ars->fd, NULL, NULL);
    if (client < 0) continue;
    char *method, *path, *body;
    char* raw = read_http(client, &method, &path, &body);
    char id[128] = "";
    char artifact[256] = "";
    int ok = 0;
    iya_saml_read_artifact_resolve(body, sp_cert, id, sizeof id, artifact, sizeof artifact, &ok);
    char* message = NULL;
    pthread_mutex_lock(&ars->mu);
    if (ok && ars->store_art && strcmp(ars->store_art, artifact) == 0) {
      message = ars->store_xml ? dup_str(ars->store_xml) : dup_str("");
      snprintf(ars->resolved, sizeof ars->resolved, "%s", artifact);
      free(ars->store_art);
      free(ars->store_xml);
      ars->store_art = NULL;
      ars->store_xml = NULL;
    }
    pthread_mutex_unlock(&ars->mu);
    char* now = iso_off(0);
    char* response_id = new_id();
    size_t cap = (message ? strlen(message) : 0) + 1024;
    char* answer = malloc(cap);
    snprintf(answer, cap,
             "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
             "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\" InResponseTo=\"%s\">"
             "<saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>%s"
             "</samlp:ArtifactResponse></soap:Body></soap:Envelope>",
             response_id, now, id, kIdp, message ? message : "");
    http_write(client, 200, "text/xml", answer);
    free(answer);
    free(now);
    free(response_id);
    free(message);
    free(method);
    free(path);
    free(body);
    free(raw);
    close(client);
  }
  return NULL;
}

static Ars* start_ars(void) {
  Ars* ars = calloc(1, sizeof *ars);
  pthread_mutex_init(&ars->mu, NULL);
  ars->fd = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(ars->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  bind(ars->fd, (struct sockaddr*)&addr, sizeof addr);
  listen(ars->fd, 16);
  socklen_t len = sizeof addr;
  getsockname(ars->fd, (struct sockaddr*)&addr, &len);
  snprintf(ars->url, sizeof ars->url, "http://127.0.0.1:%d/ars", ntohs(addr.sin_port));
  pthread_create(&ars->thread, NULL, ars_thread, ars);
  return ars;
}

static void stop_ars(Ars* ars) {
  ars->stop = 1;
  pthread_join(ars->thread, NULL);
  close(ars->fd);
  free(ars->store_art);
  free(ars->store_xml);
  pthread_mutex_destroy(&ars->mu);
  free(ars);
}

typedef struct {
  char jti[80];
  char* token;
} SetItem;

typedef struct {
  int fd;
  pthread_t thread;
  char url[128];
  pthread_mutex_t mu;
  pthread_cond_t entered;
  pthread_cond_t release;
  int hold;
  int entered_flag;
  int release_flag;
  int once;
  int created;
  char stream[2048];
  SetItem queue[32];
  int queue_n;
  char acked[32][80];
  int acked_n;
  char erred[32][80];
  int erred_n;
  int stop;
  char* jwk;
} Tx;

static char* jwk_of(EVP_PKEY* key) {
  BIGNUM* n = NULL;
  BIGNUM* e = NULL;
  EVP_PKEY_get_bn_param(key, "n", &n);
  EVP_PKEY_get_bn_param(key, "e", &e);
  int n_len = BN_num_bytes(n);
  int e_len = BN_num_bytes(e);
  unsigned char* nb = malloc((size_t)n_len);
  unsigned char* eb = malloc((size_t)e_len);
  BN_bn2bin(n, nb);
  BN_bn2bin(e, eb);
  char* ns = b64url(nb, (size_t)n_len);
  char* es = b64url(eb, (size_t)e_len);
  char* out = malloc(strlen(ns) + strlen(es) + 128);
  sprintf(out, "{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\",\"kid\":\"k1\",\"alg\":\"RS256\",\"use\":\"sig\"}", ns, es);
  free(nb);
  free(eb);
  free(ns);
  free(es);
  BN_free(n);
  BN_free(e);
  return out;
}

static char* sign_jws(const char* payload, EVP_PKEY* key, const char* header_json) {
  const char* header = header_json ? header_json : "{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"secevent+jwt\"}";
  char* h = b64url((const unsigned char*)header, strlen(header));
  char* p = b64url((const unsigned char*)payload, strlen(payload));
  char* signing = malloc(strlen(h) + strlen(p) + 2);
  sprintf(signing, "%s.%s", h, p);
  char* sig = dup_str("");
  if (header_json == NULL || (strstr(header, "\"alg\":\"RS256\"") && !strstr(header, "\"alg\":\"none\"") && !strstr(header, "HS256"))) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = 0;
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(ctx, signing, strlen(signing));
    EVP_DigestSignFinal(ctx, NULL, &len);
    unsigned char* raw = malloc(len);
    EVP_DigestSignFinal(ctx, raw, &len);
    EVP_MD_CTX_free(ctx);
    free(sig);
    sig = b64url(raw, len);
    free(raw);
  }
  char* out = malloc(strlen(signing) + strlen(sig) + 2);
  sprintf(out, "%s.%s", signing, sig);
  free(h);
  free(p);
  free(signing);
  free(sig);
  return out;
}

static void take_strings(const char* start, const char* end, char list[][80], int* count, int max_items) {
  const char* p = start;
  while (p && p < end && *count < max_items) {
    const char* q1 = strchr(p, '"');
    if (!q1 || q1 >= end) break;
    const char* q2 = strchr(q1 + 1, '"');
    if (!q2 || q2 >= end) break;
    size_t n = (size_t)(q2 - q1 - 1);
    if (n > 8 && n < 80) {
      memcpy(list[*count], q1 + 1, n);
      list[*count][n] = '\0';
      (*count)++;
    }
    p = q2 + 1;
  }
}

static void* tx_thread(void* arg) {
  Tx* tx = arg;
  while (!tx->stop) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(tx->fd, &fds);
    struct timeval tv = {0, 200000};
    if (select(tx->fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
    int client = accept(tx->fd, NULL, NULL);
    if (client < 0) continue;
    char *method, *path, *body;
    char* raw = read_http(client, &method, &path, &body);
    char* answer = NULL;
    int status = 200;
    if (strcmp(path, "/.well-known/ssf-configuration") == 0) {
      answer = malloc(1024);
      snprintf(answer, 1024,
               "{\"issuer\":\"%s\",\"jwks_uri\":\"%s/jwks\",\"configuration_endpoint\":\"%s/ssf/stream\",\"verification_endpoint\":\"%s/ssf/verify\","
               "\"delivery_methods_supported\":[\"urn:ietf:rfc:8936\"]}",
               tx->url, tx->url, tx->url, tx->url);
    } else if (strcmp(path, "/jwks") == 0) {
      answer = malloc(strlen(tx->jwk) + 32);
      sprintf(answer, "{\"keys\":[%s]}", tx->jwk);
    } else if (strcmp(path, "/ssf/stream") == 0 && strcmp(method, "GET") == 0) {
      pthread_mutex_lock(&tx->mu);
      if (tx->stream[0]) {
        answer = malloc(strlen(tx->stream) + 8);
        sprintf(answer, "[%s]", tx->stream);
      } else answer = dup_str("[]");
      pthread_mutex_unlock(&tx->mu);
    } else if (strcmp(path, "/ssf/stream") == 0 && strcmp(method, "POST") == 0) {
      pthread_mutex_lock(&tx->mu);
      tx->created++;
      snprintf(tx->stream, sizeof tx->stream,
               "{\"stream_id\":\"s%d\",\"iss\":\"%s\",\"aud\":\"my-app\",\"delivery\":{\"method\":\"urn:ietf:rfc:8936\",\"endpoint_url\":\"%s/ssf/poll/s%d\"},\"events_requested\":[],\"events_delivered\":[1,2,3,4,5,6,7,8,9,10]}",
               tx->created, tx->url, tx->url, tx->created);
      answer = dup_str(tx->stream);
      pthread_mutex_unlock(&tx->mu);
      status = 201;
    } else if (strncmp(path, "/ssf/poll/", 10) == 0) {
      pthread_mutex_lock(&tx->mu);
      if (tx->hold && !tx->once) {
        tx->once = 1;
        tx->entered_flag = 1;
        pthread_cond_signal(&tx->entered);
        while (!tx->release_flag) pthread_cond_wait(&tx->release, &tx->mu);
      }
      const char* ack = strstr(body, "\"ack\"");
      if (ack) {
        const char* lb = strchr(ack, '[');
        const char* rb = lb ? strchr(lb, ']') : NULL;
        if (lb && rb) {
          char got[32][80];
          int n = 0;
          take_strings(lb, rb, got, &n, 32);
          for (int i = 0; i < n; i++) {
            snprintf(tx->acked[tx->acked_n++], 80, "%s", got[i]);
            for (int q = 0; q < tx->queue_n; q++) {
              if (strcmp(tx->queue[q].jti, got[i]) == 0) {
                free(tx->queue[q].token);
                memmove(&tx->queue[q], &tx->queue[q + 1], (size_t)(tx->queue_n - q - 1) * sizeof(SetItem));
                tx->queue_n--;
                break;
              }
            }
          }
        }
      }
      const char* errs = strstr(body, "\"setErrs\"");
      if (errs) {
        const char* lb = strchr(errs, '{');
        const char* p = lb ? lb + 1 : NULL;
        int depth = 1;
        const char* end = p;
        while (end && *end && depth) {
          if (*end == '{') depth++;
          else if (*end == '}') depth--;
          if (depth) end++;
        }
        if (p && end) {
          char got[32][80];
          int n = 0;
          take_strings(p, end, got, &n, 32);
          for (int i = 0; i < n; i++) {
            if (strcmp(got[i], "err") == 0 || strcmp(got[i], "description") == 0 || strcmp(got[i], "invalid_key") == 0 || strcmp(got[i], "invalid_request") == 0) continue;
            snprintf(tx->erred[tx->erred_n++], 80, "%s", got[i]);
            for (int q = 0; q < tx->queue_n; q++) {
              if (strcmp(tx->queue[q].jti, got[i]) == 0) {
                free(tx->queue[q].token);
                memmove(&tx->queue[q], &tx->queue[q + 1], (size_t)(tx->queue_n - q - 1) * sizeof(SetItem));
                tx->queue_n--;
                break;
              }
            }
          }
        }
      }
      size_t cap = 64;
      for (int i = 0; i < tx->queue_n; i++) cap += strlen(tx->queue[i].jti) + strlen(tx->queue[i].token) + 8;
      answer = malloc(cap);
      strcpy(answer, "{\"sets\":{");
      for (int i = 0; i < tx->queue_n; i++) {
        if (i) strcat(answer, ",");
        strcat(answer, "\"");
        strcat(answer, tx->queue[i].jti);
        strcat(answer, "\":\"");
        strcat(answer, tx->queue[i].token);
        strcat(answer, "\"");
      }
      strcat(answer, "},\"moreAvailable\":false}");
      pthread_mutex_unlock(&tx->mu);
    } else {
      status = 404;
      answer = dup_str("{\"err\":\"not found\"}");
    }
    char header[128];
    int n = snprintf(header, sizeof header, "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status, strlen(answer));
    send(client, header, (size_t)n, MSG_NOSIGNAL);
    send(client, answer, strlen(answer), MSG_NOSIGNAL);
    free(answer);
    free(method);
    free(path);
    free(body);
    free(raw);
    close(client);
  }
  return NULL;
}

static Tx* start_tx(void) {
  Tx* tx = calloc(1, sizeof *tx);
  pthread_mutex_init(&tx->mu, NULL);
  pthread_cond_init(&tx->entered, NULL);
  pthread_cond_init(&tx->release, NULL);
  tx->jwk = jwk_of(tx_key);
  tx->fd = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  setsockopt(tx->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(tx->fd, (struct sockaddr*)&addr, sizeof addr);
  listen(tx->fd, 16);
  socklen_t len = sizeof addr;
  getsockname(tx->fd, (struct sockaddr*)&addr, &len);
  snprintf(tx->url, sizeof tx->url, "http://127.0.0.1:%d", ntohs(addr.sin_port));
  pthread_create(&tx->thread, NULL, tx_thread, tx);
  return tx;
}

static void stop_tx(Tx* tx) {
  tx->stop = 1;
  pthread_mutex_lock(&tx->mu);
  tx->release_flag = 1;
  pthread_cond_broadcast(&tx->release);
  pthread_mutex_unlock(&tx->mu);
  pthread_join(tx->thread, NULL);
  close(tx->fd);
  for (int i = 0; i < tx->queue_n; i++) free(tx->queue[i].token);
  free(tx->jwk);
  pthread_mutex_destroy(&tx->mu);
  pthread_cond_destroy(&tx->entered);
  pthread_cond_destroy(&tx->release);
  free(tx);
}

static char* put_set(Tx* tx, const char* event_type, const char* sub_json, const char* extra, EVP_PKEY* key, const char* aud, const char* iss) {
  if (!key) key = tx_key;
  if (!aud || !aud[0]) aud = "my-app";
  if (!iss || !iss[0]) iss = tx->url;
  char* jti = new_id();
  memmove(jti, jti + 1, strlen(jti));
  char* payload = malloc(strlen(event_type) + strlen(sub_json) + strlen(iss) + strlen(aud) + (extra ? strlen(extra) : 0) + 256);
  sprintf(payload, "{\"iss\":\"%s\",\"aud\":\"%s\",\"jti\":\"%s\",\"iat\":1,\"sub_id\":%s,\"events\":{\"%s\":{\"event_timestamp\":1%s%s}}}", iss, aud, jti, sub_json, event_type,
          extra && extra[0] ? "," : "", extra ? extra : "");
  char* token = sign_jws(payload, key, NULL);
  pthread_mutex_lock(&tx->mu);
  snprintf(tx->queue[tx->queue_n].jti, sizeof tx->queue[tx->queue_n].jti, "%s", jti);
  tx->queue[tx->queue_n].token = token;
  tx->queue_n++;
  pthread_mutex_unlock(&tx->mu);
  free(payload);
  return jti;
}

static int list_has(char list[][80], int n, const char* want) {
  for (int i = 0; i < n; i++)
    if (strcmp(list[i], want) == 0) return 1;
  return 0;
}

static int init_keys(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  if (iya_saml_create_key_pair("sp.test", 30, 2048, &sp_key, &sp_cert, &err) != 0) return fail_err("sp key", &err);
  if (iya_saml_create_key_pair("idp.test", 30, 2048, &idp_key, &idp_cert, &err) != 0) return fail_err("idp key", &err);
  sp_pkey = pem_key(sp_key);
  idp_pkey = pem_key(idp_key);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &tx_key);
  EVP_PKEY_keygen(ctx, &other_key);
  EVP_PKEY_CTX_free(ctx);
  return sp_pkey && idp_pkey && tx_key && other_key ? 0 : fail("keys");
}

static int test_refuses_config(void) {
  char* json = config_json(NULL, "");
  char* bad = malloc(strlen(json) + 32);
  char* key_at = strstr(json, "\"privateKey\":");
  if (!key_at) return fail("json shape");
  size_t head = (size_t)(key_at - json);
  sprintf(bad, "%.*s\"privateKey\":null%s", (int)head, json, strchr(key_at, ',') );
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = iya_saml_create(bad, "", &err);
  if (sp || strcmp(err.code, "config") != 0 || !contains(err.message, "privateKey")) {
    printf("FAIL missing key %s\n", err.message);
    free(json);
    free(bad);
    return 1;
  }
  free(bad);
  free(json);
  char* cert = json_quote(idp_cert);
  size_t cap = strlen(cert) + 32;
  char* extra = malloc(cap);
  snprintf(extra, cap, "\"certificate\":%s", cert);
  json = config_json(extra, "");
  memset(&err, 0, sizeof err);
  sp = iya_saml_create(json, "", &err);
  int rc = 0;
  if (sp || strcmp(err.code, "config") != 0 || !contains(err.message, "not for the private key")) rc = fail(err.message);
  iya_saml_sp_free(sp);
  free(cert);
  free(extra);
  free(json);
  return rc;
}

static int test_reads_idp(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  int rc = 0;
  if (strcmp(iya_saml_idp_entity_id(sp), kIdp) != 0) rc = fail("entity");
  const char* sso = iya_saml_idp_sso(sp, "redirect");
  if (!rc && (!sso || strcmp(sso, kSso) != 0)) rc = fail("sso");
  if (!rc && iya_saml_idp_certificate_count(sp) != 1) rc = fail("certs");
  iya_saml_sp_free(sp);
  return rc;
}

static int test_metadata(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* xml = NULL;
  if (iya_saml_metadata(sp, &xml, &err) != 0) return fail_err("metadata", &err);
  int rc = 0;
  if (!contains(xml, "HTTP-POST") || !contains(xml, "HTTP-Redirect") || !contains(xml, "HTTP-Artifact")) rc = fail("bindings");
  const char* post = strstr(xml, "HTTP-POST");
  const char* redir = strstr(xml, "HTTP-Redirect");
  const char* art = strstr(xml, "HTTP-Artifact");
  if (!rc && !(post && redir && art && post < redir && redir < art)) rc = fail("binding order");
  if (!rc && !contains(xml, "AuthnRequestsSigned=\"true\"")) rc = fail("signed requests");
  if (!rc && !contains(xml, "xmlenc11#aes256-gcm")) rc = fail("encryption");
  if (!rc && !contains(xml, kAcs)) rc = fail("acs");
  iya_saml_string_free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_omits_signals(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  if (iya_saml_has_signals(sp)) return fail("signals present");
  if (strcmp(iya_saml_entity_id(sp), kSp) != 0 || strcmp(iya_saml_acs_url(sp), kAcs) != 0 || strcmp(iya_saml_request_binding(sp), "redirect") != 0 ||
      strcmp(iya_saml_response_binding(sp), "post") != 0)
    return fail("fields");
  iya_saml_sp* explicit_true = must_sp("\"signals\":true", "", &err);
  if (!explicit_true) return fail_err("true", &err);
  int rc = 0;
  if (iya_saml_has_signals(explicit_true)) rc = fail("explicit true stored");
  if (!rc && (strcmp(iya_saml_entity_id(explicit_true), iya_saml_entity_id(sp)) != 0 || strcmp(iya_saml_acs_url(explicit_true), iya_saml_acs_url(sp)) != 0)) rc = fail("endpoints");
  iya_saml_sp_free(sp);
  iya_saml_sp_free(explicit_true);
  return rc;
}

static int test_signals_false(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"signals\":false,\"wantAssertionsEncrypted\":true", "", &err);
  if (!sp) return fail_err("create", &err);
  int rc = 0;
  if (!iya_saml_has_signals(sp) || iya_saml_signals_value(sp)) rc = fail("signals false");
  if (!rc && (strcmp(iya_saml_entity_id(sp), kSp) != 0 || strcmp(iya_saml_acs_url(sp), kAcs) != 0 || strcmp(iya_saml_request_binding(sp), "redirect") != 0 ||
              strcmp(iya_saml_response_binding(sp), "post") != 0))
    rc = fail("saml fields");
  if (!rc && (!iya_saml_want_assertions_signed(sp) || !iya_saml_want_assertions_encrypted(sp) || iya_saml_allow_unsolicited(sp) || iya_saml_clock_skew_ms(sp) != 60000))
    rc = fail("flags");
  if (!rc && strcmp(iya_saml_idp_entity_id(sp), kIdp) != 0) rc = fail("idp");
  iya_saml_sp_free(sp);
  return rc;
}

static int test_signals_bad(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"signals\":\"no\"", "", &err);
  if (sp || strcmp(err.code, "config") != 0 || strcmp(err.message, "signals must be true or false") != 0) {
    printf("FAIL %s\n", err.message);
    iya_saml_sp_free(sp);
    return 1;
  }
  return 0;
}

static int test_redirect_authn(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  iya_saml_login_options opt;
  memset(&opt, 0, sizeof opt);
  const char* home = "/home";
  opt.relay_state = home;
  iya_saml_login_request req;
  memset(&req, 0, sizeof req);
  if (iya_saml_login(sp, &opt, &req, &err) != 0) return fail_err("login", &err);
  int rc = 0;
  if (strcmp(req.binding, "redirect") != 0 || strncmp(req.url, kSso, strlen(kSso)) != 0 || !strstr(req.url, "?")) rc = fail("url");
  char* query = dup_str(strchr(req.url, '?') + 1);
  char* sig_at = strstr(query, "&Signature=");
  if (!rc && !sig_at) rc = fail("signature");
  if (!rc) {
    *sig_at = '\0';
    char* sig = uri_unescape(sig_at + strlen("&Signature="));
    size_t sig_len = 0;
    unsigned char* raw = b64_dec(sig, &sig_len);
    EVP_PKEY* pub = pem_pub(sp_cert);
    if (!raw || !rsa_verify(pub, query, raw, sig_len)) rc = fail("verify query");
    EVP_PKEY_free(pub);
    free(raw);
    free(sig);
  }
  char* saml = NULL;
  char* relay = NULL;
  char* cursor = dup_str(strchr(req.url, '?') + 1);
  char* save = cursor;
  for (char* part = strtok(cursor, "&"); part; part = strtok(NULL, "&")) {
    if (strncmp(part, "SAMLRequest=", 12) == 0) saml = uri_unescape(part + 12);
    if (strncmp(part, "RelayState=", 11) == 0) relay = uri_unescape(part + 11);
  }
  if (!rc && (!relay || strcmp(relay, "/home") != 0)) rc = fail("relay");
  if (!rc && saml) {
    size_t n = 0;
    unsigned char* raw = b64_dec(saml, &n);
    char* xml = raw ? inflate_raw(raw, n) : NULL;
    if (!xml || !contains(xml, req.id) || !contains(xml, "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"") || !contains(xml, kSso)) rc = fail(xml ? xml : "inflate");
    free(xml);
    free(raw);
  }
  free(save);
  free(saml);
  free(relay);
  free(query);
  iya_saml_login_request_free(&req);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_post_authn(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"requestBinding\":\"post\"", "", &err);
  if (!sp) return fail_err("create", &err);
  iya_saml_login_options opt;
  memset(&opt, 0, sizeof opt);
  opt.response_binding = "artifact";
  opt.nonce = "abc";
  iya_saml_login_request req;
  memset(&req, 0, sizeof req);
  if (iya_saml_login(sp, &opt, &req, &err) != 0) return fail_err("login", &err);
  size_t n = 0;
  unsigned char* raw = b64_dec(req.saml_request, &n);
  char* xml = malloc(n + 1);
  memcpy(xml, raw, n);
  xml[n] = '\0';
  int rc = 0;
  if (strcmp(req.binding, "post") != 0) rc = fail("binding");
  if (!rc && (!strstr(xml, "</saml:Issuer><ds:Signature") || !contains(xml, "HTTP-Artifact"))) rc = fail(xml);
  if (!rc && iya_saml_signature_verifies(xml, sp_cert, &err) != 0) rc = fail_err("verify", &err);
  if (!rc && (!contains(req.html, "<script nonce=\"abc\">") || !contains(req.html, "<button type=\"submit\">"))) rc = fail(req.html);
  free(xml);
  free(raw);
  iya_saml_login_request_free(&req);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_subject_hint(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"requestBinding\":\"post\"", "", &err);
  if (!sp) return fail_err("create", &err);
  iya_saml_login_options opt;
  memset(&opt, 0, sizeof opt);
  opt.subject_hint = "alice<&>";
  opt.subject_hint_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
  opt.force_authn = 1;
  iya_saml_login_request req;
  memset(&req, 0, sizeof req);
  if (iya_saml_login(sp, &opt, &req, &err) != 0) return fail_err("login", &err);
  size_t n = 0;
  unsigned char* raw = b64_dec(req.saml_request, &n);
  char* xml = malloc(n + 1);
  memcpy(xml, raw, n);
  xml[n] = '\0';
  int rc = 0;
  const char* want = "</ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy";
  if (!contains(xml, want)) rc = fail(xml);
  if (!rc && !contains(xml, "ForceAuthn=\"true\"")) rc = fail("force");
  if (!rc && iya_saml_signature_verifies(xml, sp_cert, &err) != 0) rc = fail_err("verify", &err);
  iya_saml_login_request plain;
  memset(&plain, 0, sizeof plain);
  memset(&opt, 0, sizeof opt);
  if (!rc && iya_saml_login(sp, &opt, &plain, &err) != 0) rc = fail_err("plain", &err);
  if (!rc && contains(plain.xml, "<saml:Subject>")) rc = fail("subject leaked");
  free(xml);
  free(raw);
  iya_saml_login_request_free(&req);
  iya_saml_login_request_free(&plain);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_relay_limit(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char relay[82];
  memset(relay, 'x', 81);
  relay[81] = '\0';
  iya_saml_login_options opt;
  memset(&opt, 0, sizeof opt);
  opt.relay_state = relay;
  iya_saml_login_request req;
  memset(&req, 0, sizeof req);
  int rc = iya_saml_login(sp, &opt, &req, &err);
  int bad = rc == 0 || !contains(err.message, "80 bytes");
  iya_saml_login_request_free(&req);
  iya_saml_sp_free(sp);
  return bad ? fail(err.message) : 0;
}

static int accept_post(iya_saml_sp* sp, const char* xml, const char* request_id, const char* relay, iya_saml_acs_result* login) {
  char* body = post_body(xml, relay);
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  const char* ids[1] = {request_id};
  int count = request_id && request_id[0] ? 1 : 0;
  int rc = iya_saml_acs(sp, "POST", "/saml/acs", body, count ? ids : NULL, count, login, &err);
  free(body);
  if (rc != 0) return fail_err("acs", &err);
  return 0;
}

static int test_signed_both(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_req1";
  opt.sign = 1;
  char* xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  int rc = accept_post(sp, xml, "_req1", "/home", &login);
  if (!rc && (strcmp(login.name_id, "alice-1234") != 0 || strcmp(login.name_id_format, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") != 0 || strcmp(login.session_index, "_session1") != 0))
    rc = fail("who");
  if (!rc && (!login.relay_state || strcmp(login.relay_state, "/home") != 0 || strcmp(login.binding, "post") != 0)) rc = fail("relay");
  if (!rc && (!attr_has(&login, "groups", "staff") || !attr_has(&login, "groups", "admins"))) rc = fail("groups");
  if (!rc && (!attr_has(&login, "urn:oid:0.9.2342.19200300.100.1.3", "alice@example.com") || strcmp(attr_friendly(&login, "urn:oid:0.9.2342.19200300.100.1.3"), "mail") != 0)) rc = fail("mail");
  if (!rc && strcmp(login.authn_context, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport") != 0) rc = fail("context");
  iya_saml_login_free(&login);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_signed_assertion_only(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_req1";
  char* xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  int rc = accept_post(sp, xml, "_req1", NULL, &login);
  if (!rc && strcmp(login.name_id, "alice-1234") != 0) rc = fail("name");
  iya_saml_login_free(&login);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_unsigned_assertion(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* raw = assertion_xml((AssertionOpt){.in_response_to = "_r"}, NULL);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.sign = 1;
  opt.assertion = raw;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "validation", "not signed");
  free(body);
  iya_saml_sp* lax = must_sp("\"wantAssertionsSigned\":false", "", &err);
  if (!rc && !lax) rc = fail_err("lax", &err);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  if (!rc) rc = accept_post(lax, xml, "_r", NULL, &login);
  if (!rc && strcmp(login.name_id, "alice-1234") != 0) rc = fail("name");
  iya_saml_login_free(&login);
  free(raw);
  free(xml);
  iya_saml_sp_free(sp);
  iya_saml_sp_free(lax);
  return rc;
}

static int test_nothing_signed(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"wantAssertionsSigned\":false", "", &err);
  if (!sp) return fail_err("create", &err);
  char* raw = assertion_xml((AssertionOpt){.in_response_to = "_r"}, NULL);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = raw;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "validation", "neither");
  free(body);
  free(raw);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_altered(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  char* xml = response_xml(opt);
  char* at = strstr(xml, "alice-1234");
  if (at) memcpy(at, "mallory00", 9);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "signature", NULL);
  free(body);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_other_key(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* id = NULL;
  char* raw = assertion_xml((AssertionOpt){.in_response_to = "_r"}, &id);
  char* signed_xml = sign_xml(raw, id, sp_key, sp_cert);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = signed_xml;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "signature", "does not verify");
  free(body);
  free(xml);
  free(signed_xml);
  free(raw);
  free(id);
  iya_saml_sp_free(sp);
  return rc;
}

static char* replace_once(const char* text, const char* from, const char* to) {
  const char* at = strstr(text, from);
  if (!at) return dup_str(text);
  size_t cap = strlen(text) + strlen(to) + 1;
  char* out = malloc(cap);
  size_t head = (size_t)(at - text);
  memcpy(out, text, head);
  memcpy(out + head, to, strlen(to));
  strcpy(out + head + strlen(to), at + strlen(from));
  return out;
}

static int test_wrapping(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* id = NULL;
  char* signed_xml = signed_assertion((AssertionOpt){.in_response_to = "_r"}, &id);
  char* forged = assertion_xml((AssertionOpt){.in_response_to = "_r", .name_id = "mallory"}, NULL);
  size_t cap = strlen(forged) + strlen(signed_xml) + 8;
  char* both = malloc(cap);
  sprintf(both, "%s%s", forged, signed_xml);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = both;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "validation", "exactly one");
  free(body);
  free(xml);
  char id_attr[96];
  snprintf(id_attr, sizeof id_attr, "ID=\"%s\"", id);
  char* first_id = strstr(forged, "ID=\"");
  char* id_end = first_id ? strchr(first_id + 4, '"') : NULL;
  char* hidden = NULL;
  if (first_id && id_end) {
    size_t hcap = strlen(forged) + strlen(id) + 8;
    hidden = malloc(hcap);
    size_t head = (size_t)(first_id - forged);
    memcpy(hidden, forged, head);
    sprintf(hidden + head, "%s%s", id_attr, id_end + 1);
  }
  char* wrapped = hidden ? replace_once(hidden, "</saml:Assertion>", "") : NULL;
  if (wrapped) {
    char* full = malloc(strlen(wrapped) + strlen(signed_xml) + 64);
    sprintf(full, "%s<saml:Advice>%s</saml:Advice></saml:Assertion>", wrapped, signed_xml);
    free(wrapped);
    wrapped = full;
  }
  opt.assertion = wrapped;
  xml = response_xml(opt);
  body = post_body(xml, NULL);
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", body, "_r", "signature", "two elements");
  free(body);
  free(xml);
  const char* sig_start = strstr(signed_xml, "<ds:Signature");
  const char* sig_end = sig_start ? strstr(sig_start, "</ds:Signature>") : NULL;
  char* sig = NULL;
  if (sig_start && sig_end) {
    size_t n = (size_t)(sig_end + strlen("</ds:Signature>") - sig_start);
    sig = malloc(n + 1);
    memcpy(sig, sig_start, n);
    sig[n] = '\0';
  }
  char* moved = NULL;
  if (sig) {
    char* at = strstr(forged, "</saml:Issuer>");
    if (at) {
      moved = malloc(strlen(forged) + strlen(sig) + 1);
      size_t head = (size_t)(at + strlen("</saml:Issuer>") - forged);
      memcpy(moved, forged, head);
      memcpy(moved + head, sig, strlen(sig));
      strcpy(moved + head + strlen(sig), at + strlen("</saml:Issuer>"));
    }
  }
  opt.assertion = moved ? moved : forged;
  xml = response_xml(opt);
  body = post_body(xml, NULL);
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", body, "_r", "signature", "refers to");
  free(body);
  free(xml);
  free(sig);
  free(moved);
  free(wrapped);
  free(hidden);
  free(both);
  free(forged);
  free(signed_xml);
  free(id);
  iya_saml_sp_free(sp);
  return rc;
}

static int reject_xml(iya_saml_sp* sp, const char* xml, const char* request, const char* pattern) {
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, request, "validation", pattern);
  free(body);
  free((void*)xml);
  return rc;
}

static int test_audience_expiry(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* audience = signed_assertion((AssertionOpt){.in_response_to = "_r", .audience = "https://other.test"}, NULL);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = audience;
  opt.has_assertion = 1;
  int rc = reject_xml(sp, response_xml(opt), "_r", "not for");
  char* recipient = signed_assertion((AssertionOpt){.in_response_to = "_r", .recipient = "https://other.test/acs"}, NULL);
  opt.assertion = recipient;
  if (!rc) rc = reject_xml(sp, response_xml(opt), "_r", "Recipient");
  char* expired = signed_assertion((AssertionOpt){.in_response_to = "_r", .has_expiry = 1, .expiry_ms = -120000}, NULL);
  opt.assertion = expired;
  if (!rc) rc = reject_xml(sp, response_xml(opt), "_r", "expired");
  opt.has_assertion = 0;
  opt.assertion = NULL;
  opt.has_destination = 1;
  opt.destination = "https://other.test/acs";
  if (!rc) rc = reject_xml(sp, response_xml(opt), "_r", "addressed to");
  char* issuer = signed_assertion((AssertionOpt){.in_response_to = "_r", .issuer = "https://evil.test"}, NULL);
  opt.has_destination = 0;
  opt.has_assertion = 1;
  opt.assertion = issuer;
  if (!rc) rc = reject_xml(sp, response_xml(opt), "_r", "issued by");
  free(audience);
  free(recipient);
  free(expired);
  free(issuer);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_in_response_to(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_other", "validation", "not a request this browser");
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", body, "", "validation", "not a request this browser");
  free(body);
  free(xml);
  opt.in_response_to = NULL;
  xml = response_xml(opt);
  body = post_body(xml, NULL);
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", body, "", "validation", "unsolicited");
  free(body);
  iya_saml_sp* open = must_sp("\"allowUnsolicited\":true", "", &err);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  if (!rc && !open) rc = fail_err("open", &err);
  if (!rc) rc = accept_post(open, xml, "", NULL, &login);
  if (!rc && login.in_response_to) rc = fail("in response to");
  iya_saml_login_free(&login);
  free(xml);
  iya_saml_sp_free(sp);
  iya_saml_sp_free(open);
  return rc;
}

static int test_replay(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.sign = 1;
  char* xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  int rc = accept_post(sp, xml, "_r", NULL, &login);
  iya_saml_login_free(&login);
  char* body = post_body(xml, NULL);
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", body, "_r", "replay", NULL);
  free(body);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_status(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.status = "urn:oasis:names:tc:SAML:2.0:status:Responder";
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  const char* ids[] = {"_r"};
  int rc = iya_saml_acs(sp, "POST", "/saml/acs", body, ids, 1, &login, &err);
  int bad = rc == 0 || strcmp(err.code, "status") != 0 || strcmp(err.status_code, opt.status) != 0;
  if (bad) printf("FAIL status %s %s\n", err.code, err.status_code);
  iya_saml_login_free(&login);
  free(body);
  free(xml);
  iya_saml_sp_free(sp);
  return bad;
}

static int test_doctype(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  char* xml = response_xml(opt);
  char* doctored = malloc(strlen(xml) + 64);
  sprintf(doctored, "<!DOCTYPE x [<!ENTITY e \"x\">]>%s", xml);
  char* body = post_body(doctored, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "xml", "DOCTYPE");
  free(body);
  free(doctored);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_decrypt(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  const char* ciphers[] = {"aes-256-gcm", "aes-128-cbc"};
  int rc = 0;
  for (int i = 0; i < 2 && !rc; i++) {
    char* made = signed_assertion((AssertionOpt){.in_response_to = "_r"}, NULL);
    char* enc = encrypt_assertion(made, ciphers[i], "", "");
    ResponseOpt opt = {0};
    opt.in_response_to = "_r";
    opt.sign = 1;
    opt.assertion = enc;
    opt.has_assertion = 1;
    char* xml = response_xml(opt);
    iya_saml_acs_result login;
    memset(&login, 0, sizeof login);
    rc = accept_post(sp, xml, "_r", NULL, &login);
    if (!rc && (strcmp(login.name_id, "alice-1234") != 0 || !login.encrypted)) rc = fail(ciphers[i]);
    iya_saml_login_free(&login);
    free(xml);
    free(enc);
    free(made);
  }
  char* made = signed_assertion((AssertionOpt){.in_response_to = "_r"}, NULL);
  char* enc = encrypt_assertion(made, "aes-256-gcm", "oaep256", "");
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = enc;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  if (!rc) rc = accept_post(sp, xml, "_r", NULL, &login);
  if (!rc && strcmp(login.name_id, "alice-1234") != 0) rc = fail("oaep");
  iya_saml_login_free(&login);
  free(xml);
  free(enc);
  free(made);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_require_encryption(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"wantAssertionsEncrypted\":true", "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.sign = 1;
  char* xml = response_xml(opt);
  char* body = post_body(xml, NULL);
  int rc = rejects(sp, "POST", "/saml/acs", body, "_r", "validation", "not encrypted");
  free(body);
  free(xml);
  char* made = signed_assertion((AssertionOpt){.in_response_to = "_r"}, NULL);
  char* enc = encrypt_assertion(made, "", "", "");
  opt.sign = 0;
  opt.assertion = enc;
  opt.has_assertion = 1;
  xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  if (!rc) rc = accept_post(sp, xml, "_r", NULL, &login);
  if (!rc && !login.encrypted) rc = fail("encrypted flag");
  iya_saml_login_free(&login);
  free(xml);
  free(enc);
  free(made);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_altered_cipher(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* made = signed_assertion((AssertionOpt){.in_response_to = "_r"}, NULL);
  char* enc = encrypt_assertion(made, "", "", "");
  char* last = NULL;
  char* cursor = enc;
  while ((cursor = strstr(cursor, "<xenc:CipherValue>"))) {
    last = cursor + strlen("<xenc:CipherValue>");
    cursor++;
  }
  char* end = last ? strstr(last, "</xenc:CipherValue>") : NULL;
  int rc = 0;
  if (!last || !end) rc = fail("cipher");
  else {
    size_t n = (size_t)(end - last);
    char* value = malloc(n + 1);
    memcpy(value, last, n);
    value[n] = '\0';
    size_t raw_len = 0;
    unsigned char* raw = b64_dec(value, &raw_len);
    if (!raw || raw_len < 21) rc = fail("decode cipher");
    else {
      raw[20] ^= 1;
      char* flipped = b64(raw, raw_len);
      char* changed = malloc(strlen(enc) + strlen(flipped) + 1);
      size_t head = (size_t)(last - enc);
      memcpy(changed, enc, head);
      memcpy(changed + head, flipped, strlen(flipped));
      strcpy(changed + head + strlen(flipped), end);
      ResponseOpt opt = {0};
      opt.in_response_to = "_r";
      opt.assertion = changed;
      opt.has_assertion = 1;
      char* xml = response_xml(opt);
      char* body = post_body(xml, NULL);
      rc = rejects(sp, "POST", "/saml/acs", body, "_r", "decryption", NULL);
      free(body);
      free(xml);
      free(changed);
      free(flipped);
    }
    free(raw);
    free(value);
  }
  free(enc);
  free(made);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_encrypted_attribute(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  char* secret = encrypt_assertion("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>",
                                   "aes-256-gcm", "oaep256", "EncryptedAttribute");
  char* id = NULL;
  char* raw = assertion_xml((AssertionOpt){.in_response_to = "_r", .extra = secret}, &id);
  char* signed_xml = sign_xml(raw, id, NULL, NULL);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  opt.assertion = signed_xml;
  opt.has_assertion = 1;
  char* xml = response_xml(opt);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  int rc = accept_post(sp, xml, "_r", NULL, &login);
  if (!rc && !attr_has(&login, "employeeNumber", "E-42")) rc = fail("employee");
  iya_saml_login_free(&login);
  free(xml);
  free(signed_xml);
  free(raw);
  free(id);
  free(secret);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_redirect_response(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  char* xml = response_xml(opt);
  char* query = redirect_response_query(xml, "/there", NULL);
  char* url = malloc(strlen(query) + 16);
  sprintf(url, "/saml/acs?%s", query);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  const char* ids[] = {"_r"};
  int rc = iya_saml_acs(sp, "GET", url, NULL, ids, 1, &login, &err);
  if (rc != 0) rc = fail_err("acs", &err);
  else if (strcmp(login.binding, "redirect") != 0 || !login.relay_state || strcmp(login.relay_state, "/there") != 0) rc = fail("redirect login");
  iya_saml_login_free(&login);
  free(url);
  free(query);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_bad_query_sig(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  ResponseOpt opt = {0};
  opt.in_response_to = "_r";
  char* xml = response_xml(opt);
  char* forged = redirect_response_query(xml, "/x", sp_pkey);
  char* url = malloc(strlen(forged) + 16);
  sprintf(url, "/saml/acs?%s", forged);
  int rc = rejects(sp, "GET", url, NULL, "_r", "signature", NULL);
  free(url);
  char* changed_src = redirect_response_query(xml, "/x", NULL);
  char* changed = replace_once(changed_src, "RelayState=%2Fx", "RelayState=%2Fy");
  url = malloc(strlen(changed) + 16);
  sprintf(url, "/saml/acs?%s", changed);
  if (!rc) rc = rejects(sp, "GET", url, NULL, "_r", "signature", NULL);
  free(url);
  free(changed);
  free(changed_src);
  free(forged);
  free(xml);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_artifact(void) {
  Ars* ars = start_ars();
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp("\"responseBinding\":\"artifact\"", ars->url, &err);
  if (!sp) {
    stop_ars(ars);
    return fail_err("create", &err);
  }
  iya_saml_login_options opt;
  memset(&opt, 0, sizeof opt);
  iya_saml_login_request req;
  memset(&req, 0, sizeof req);
  if (iya_saml_login(sp, &opt, &req, &err) != 0) return fail_err("login", &err);
  int rc = contains(req.xml, "HTTP-Artifact") ? 0 : fail("binding");
  char* artifact = artifact_for("");
  ResponseOpt response = {0};
  response.in_response_to = req.id;
  char* xml = response_xml(response);
  pthread_mutex_lock(&ars->mu);
  ars->store_art = dup_str(artifact);
  ars->store_xml = xml;
  pthread_mutex_unlock(&ars->mu);
  char* esc = uri_escape(artifact);
  char* url = malloc(strlen(esc) + 64);
  sprintf(url, "/saml/acs?SAMLart=%s&RelayState=%%2Fa", esc);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  const char* ids[] = {req.id};
  if (!rc && iya_saml_acs(sp, "GET", url, NULL, ids, 1, &login, &err) != 0) rc = fail_err("acs", &err);
  if (!rc && (strcmp(login.binding, "artifact") != 0 || !login.relay_state || strcmp(login.relay_state, "/a") != 0 || strcmp(login.name_id, "alice-1234") != 0)) rc = fail("who");
  if (!rc && strcmp(ars->resolved, artifact) != 0) rc = fail("resolved");
  iya_saml_login_free(&login);
  free(url);
  free(esc);
  free(artifact);
  iya_saml_login_request_free(&req);
  iya_saml_sp_free(sp);
  stop_ars(ars);
  return rc;
}

static int test_artifact_post(void) {
  Ars* ars = start_ars();
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, ars->url, &err);
  if (!sp) {
    stop_ars(ars);
    return fail_err("create", &err);
  }
  char* artifact = artifact_for("");
  ResponseOpt response = {0};
  response.in_response_to = "_r";
  pthread_mutex_lock(&ars->mu);
  ars->store_art = dup_str(artifact);
  ars->store_xml = response_xml(response);
  pthread_mutex_unlock(&ars->mu);
  char* esc = uri_escape(artifact);
  char* body = malloc(strlen(esc) + 16);
  sprintf(body, "SAMLart=%s", esc);
  iya_saml_acs_result login;
  memset(&login, 0, sizeof login);
  const char* ids[] = {"_r"};
  int rc = iya_saml_acs(sp, "POST", "/saml/acs", body, ids, 1, &login, &err);
  if (rc != 0) rc = fail_err("acs", &err);
  else if (strcmp(login.binding, "artifact") != 0) rc = fail("binding");
  iya_saml_login_free(&login);
  char* quoted = json_quote(artifact);
  char* again = malloc(strlen(quoted) + 16);
  sprintf(again, "{\"SAMLart\":%s}", quoted);
  if (!rc) rc = rejects(sp, "POST", "/saml/acs", again, "_r", "artifact", "did not resolve");
  free(again);
  free(quoted);
  free(body);
  free(esc);
  free(artifact);
  iya_saml_sp_free(sp);
  stop_ars(ars);
  return rc;
}

static int test_foreign_artifact(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "https://idp.test/saml2/ars", &err);
  if (!sp) return fail_err("create", &err);
  char* artifact = artifact_for("https://evil.test");
  char* esc = uri_escape(artifact);
  char* url = malloc(strlen(esc) + 32);
  sprintf(url, "/saml/acs?SAMLart=%s", esc);
  int rc = rejects(sp, "GET", url, NULL, "_r", "artifact", "not issued by");
  free(url);
  free(esc);
  free(artifact);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_no_message(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, "", &err);
  if (!sp) return fail_err("create", &err);
  int rc = rejects(sp, "GET", "/saml/acs", NULL, "", "binding", NULL);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_parse_xml(void) { return iya_saml_xml_well_formed("<a/>") == 1 ? 0 : fail("xml"); }

static int test_jws(void) {
  char* jwk = jwk_of(tx_key);
  char* keys = malloc(strlen(jwk) + 32);
  sprintf(keys, "{\"keys\":[%s]}", jwk);
  char* token = sign_jws("{\"a\":1}", tx_key, NULL);
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  char* payload = NULL;
  int rc = iya_saml_verify_jws(token, keys, &payload, &err);
  if (rc != 0) rc = fail_err("verify", &err);
  else if (!contains(payload, "\"a\":1") && !contains(payload, "\"a\": 1")) rc = fail(payload);
  iya_saml_string_free(payload);
  free(token);
  token = sign_jws("{\"a\":1}", other_key, NULL);
  memset(&err, 0, sizeof err);
  if (!rc && (iya_saml_verify_jws(token, keys, &payload, &err) == 0 || !contains(err.message, "does not verify"))) rc = fail(err.message);
  free(token);
  token = sign_jws("{\"a\":1}", tx_key, "{\"alg\":\"RS256\",\"kid\":\"nope\"}");
  memset(&err, 0, sizeof err);
  if (!rc && (iya_saml_verify_jws(token, keys, &payload, &err) == 0 || !contains(err.message, "no RSA signing key with kid nope"))) rc = fail(err.message);
  free(token);
  token = sign_jws("{\"a\":1}", tx_key, "{\"alg\":\"none\"}");
  memset(&err, 0, sizeof err);
  if (!rc && (iya_saml_verify_jws(token, keys, &payload, &err) == 0 || !contains(err.message, "does not verify"))) rc = fail(err.message);
  free(token);
  token = sign_jws("{\"a\":1}", tx_key, "{\"alg\":\"HS256\",\"kid\":\"k1\"}");
  memset(&err, 0, sizeof err);
  if (!rc && (iya_saml_verify_jws(token, keys, &payload, &err) == 0 || !contains(err.message, "does not verify"))) rc = fail(err.message);
  free(token);
  free(keys);
  free(jwk);
  return rc;
}

static int test_subjects(void) {
  char person[128], email[128], session[128];
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  const char* complex = "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"https://i\",\"sub\":\"urn:uuid:a\"},\"session\":{\"format\":\"opaque\",\"id\":\"S1\"}}";
  if (iya_saml_subject(complex, "https://i", person, sizeof person, email, sizeof email, session, sizeof session, &err) != 0) return fail_err("subject", &err);
  if (strcmp(person, "urn:uuid:a") != 0 || strcmp(session, "S1") != 0) return fail("complex");
  const char* foreign = "{\"format\":\"iss_sub\",\"iss\":\"https://other\",\"sub\":\"urn:uuid:a\"}";
  if (iya_saml_subject(foreign, "https://i", person, sizeof person, email, sizeof email, session, sizeof session, &err) != 0) return fail_err("foreign", &err);
  if (person[0] || email[0] || session[0]) return fail("foreign iss");
  const char* mail = "{\"format\":\"email\",\"email\":\"A@x.com\"}";
  if (iya_saml_subject(mail, "https://i", person, sizeof person, email, sizeof email, session, sizeof session, &err) != 0) return fail_err("email", &err);
  return strcmp(email, "A@x.com") == 0 ? 0 : fail(email);
}

static int test_event_names(void) {
  if (iya_saml_caep_event_count() != 8 || iya_saml_risc_event_count() != 14) return fail("counts");
  if (!contains(iya_saml_event_uri("risk_level_change"), "risk-level-change")) return fail("caep");
  if (!contains(iya_saml_event_uri("opt_out_effective"), "opt-out-effective")) return fail("risc");
  return 0;
}

typedef struct {
  char ended[8][128];
  int ended_n;
  char seen_jti[16][80];
  int seen_n;
  char errors[8][512];
  int errors_n;
  int end_fail;
  int handler_fail;
  pthread_mutex_t mu;
} Seen;

static int on_end(const char* const* ids, int count, const iya_saml_event* event, void* user, char* err, size_t err_cap) {
  (void)event;
  Seen* seen = user;
  pthread_mutex_lock(&seen->mu);
  if (seen->ended_n < 8) {
    seen->ended[seen->ended_n][0] = '\0';
    for (int i = 0; i < count; i++) {
      if (i) strncat(seen->ended[seen->ended_n], ",", 120);
      strncat(seen->ended[seen->ended_n], ids[i], 80);
    }
    seen->ended_n++;
  }
  int fail_it = seen->end_fail;
  pthread_mutex_unlock(&seen->mu);
  if (fail_it) {
    snprintf(err, err_cap, "store down");
    return 1;
  }
  return 0;
}

static int on_event(const iya_saml_event* event, void* user, char* err, size_t err_cap) {
  Seen* seen = user;
  pthread_mutex_lock(&seen->mu);
  if (seen->seen_n < 16) snprintf(seen->seen_jti[seen->seen_n++], 80, "%s", event->jti);
  int fail_it = seen->handler_fail && contains(event->type, "credential-change");
  pthread_mutex_unlock(&seen->mu);
  if (fail_it) {
    snprintf(err, err_cap, "handler bug");
    return 1;
  }
  return 0;
}

static void on_log(const char* level, const char* message, void* user) {
  Seen* seen = user;
  if (strcmp(level, "error") != 0) return;
  pthread_mutex_lock(&seen->mu);
  if (seen->errors_n < 8) snprintf(seen->errors[seen->errors_n++], 512, "%s", message);
  pthread_mutex_unlock(&seen->mu);
}

static void track(iya_saml_receiver* receiver, const char* local, const char* person, const char* session) {
  char subject[128];
  char email[128];
  snprintf(subject, sizeof subject, "urn:uuid:%s", person);
  snprintf(email, sizeof email, "%s@example.com", person);
  iya_saml_receiver_track(receiver, local, subject, email, session);
}

static void* poll_thread(void* arg) {
  iya_saml_receiver* receiver = arg;
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_receiver_poll(receiver, NULL, &err);
  return NULL;
}

static int test_shared(void) {
  Tx* tx = start_tx();
  Seen seen;
  memset(&seen, 0, sizeof seen);
  pthread_mutex_init(&seen.mu, NULL);
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_receiver* receiver = iya_saml_receiver_new(tx->url, 60000, on_end, &seen, on_log, &seen, &err);
  if (!receiver) {
    stop_tx(tx);
    return fail_err("receiver", &err);
  }
  iya_saml_receiver_on(receiver, "*", on_event, &seen);
  int rc = iya_saml_receiver_start(receiver, &err);
  if (rc != 0) rc = fail_err("start", &err);
  iya_saml_receiver_stop(receiver);
  char stream[64];
  iya_saml_receiver_stream_id(receiver, stream, sizeof stream);
  if (!rc && (tx->created != 1 || strcmp(stream, "s1") != 0)) rc = fail("stream");
  track(receiver, "L-a1", "alice", "IDP-A1");
  track(receiver, "L-a2", "alice", "IDP-A2");
  track(receiver, "L-b1", "bob", "IDP-B1");
  char sub1[256];
  snprintf(sub1, sizeof sub1, "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-A1\"}}", tx->url);
  char* j1 = put_set(tx, iya_saml_event_uri("session_revoked"), sub1, NULL, NULL, "", "");
  char sub2[256];
  snprintf(sub2, sizeof sub2, "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:bob\"}}", tx->url);
  char* j2 = put_set(tx, iya_saml_event_uri("credential_change"), sub2, "\"credential_type\":\"password\",\"change_type\":\"update\"", NULL, "", "");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("poll", &err);
  if (!rc && (seen.ended_n != 1 || strcmp(seen.ended[0], "L-a1") != 0)) rc = fail(seen.ended[0]);
  int found = 0;
  for (int i = 0; i < seen.seen_n; i++)
    if (strcmp(seen.seen_jti[i], j2) == 0) found = 1;
  if (!rc && !found) rc = fail("credential event");
  char sub3[256];
  snprintf(sub3, sizeof sub3, "{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"}", tx->url);
  char* j3 = put_set(tx, iya_saml_event_uri("account_disabled"), sub3, NULL, NULL, "", "");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("poll2", &err);
  if (!rc && (seen.ended_n < 2 || strcmp(seen.ended[1], "L-a2") != 0)) rc = fail("ended alice");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("poll3", &err);
  if (!rc && (!list_has(tx->acked, tx->acked_n, j1) || !list_has(tx->acked, tx->acked_n, j2))) rc = fail("ack");
  char* jmail = put_set(tx, iya_saml_event_uri("credential_compromise"), "{\"format\":\"email\",\"email\":\"BOB@example.com\"}", "\"credential_type\":\"password\"", NULL, "", "");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("poll mail", &err);
  if (!rc && (seen.ended_n < 3 || strcmp(seen.ended[2], "L-b1") != 0)) rc = fail("email end");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("poll4", &err);
  if (!rc && !list_has(tx->acked, tx->acked_n, j3)) rc = fail("ack j3");
  iya_saml_receiver* again = iya_saml_receiver_new(tx->url, 0, on_end, &seen, on_log, &seen, &err);
  if (!rc && !again) rc = fail_err("again", &err);
  if (!rc && iya_saml_receiver_start(again, &err) != 0) rc = fail_err("again start", &err);
  if (again) iya_saml_receiver_stop(again);
  iya_saml_receiver_stream_id(again, stream, sizeof stream);
  if (!rc && (tx->created != 1 || strcmp(stream, "s1") != 0)) rc = fail("reused");
  iya_saml_receiver_free(again);
  iya_saml_receiver_free(receiver);

  Seen forged_seen;
  memset(&forged_seen, 0, sizeof forged_seen);
  pthread_mutex_init(&forged_seen.mu, NULL);
  receiver = iya_saml_receiver_new(tx->url, 0, on_end, &forged_seen, on_log, &forged_seen, &err);
  if (!rc && iya_saml_receiver_start(receiver, &err) != 0) rc = fail_err("forged start", &err);
  if (receiver) iya_saml_receiver_stop(receiver);
  track(receiver, "L-c1", "carol", "IDP-C1");
  char subc[320];
  snprintf(subc, sizeof subc, "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:carol\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-C1\"}}", tx->url);
  char* forged = put_set(tx, iya_saml_event_uri("session_revoked"), subc, NULL, other_key, "", "");
  char* mis = put_set(tx, iya_saml_event_uri("session_revoked"), subc, NULL, NULL, "someone-else", "");
  char* foreign = put_set(tx, iya_saml_event_uri("session_revoked"), subc, NULL, NULL, "", "https://evil.example");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("forged poll", &err);
  char sessions[128];
  iya_saml_receiver_sessions_for_person(receiver, "urn:uuid:carol", sessions, sizeof sessions);
  if (!rc && (forged_seen.ended_n != 0 || strcmp(sessions, "L-c1") != 0)) rc = fail("carol kept");
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("err poll", &err);
  if (!rc && (!list_has(tx->erred, tx->erred_n, forged) || !list_has(tx->erred, tx->erred_n, mis) || !list_has(tx->erred, tx->erred_n, foreign))) rc = fail("set errs");
  iya_saml_receiver_free(receiver);
  free(forged);
  free(mis);
  free(foreign);

  Seen throwing;
  memset(&throwing, 0, sizeof throwing);
  pthread_mutex_init(&throwing.mu, NULL);
  throwing.end_fail = 1;
  throwing.handler_fail = 1;
  receiver = iya_saml_receiver_new(tx->url, 0, on_end, &throwing, on_log, &throwing, &err);
  iya_saml_receiver_on(receiver, iya_saml_event_uri("credential_change"), on_event, &throwing);
  iya_saml_receiver_on(receiver, "*", on_event, &throwing);
  if (!rc && iya_saml_receiver_start(receiver, &err) != 0) rc = fail_err("throw start", &err);
  if (receiver) iya_saml_receiver_stop(receiver);
  track(receiver, "L-d1", "dave", "IDP-D1");
  char subd[256];
  snprintf(subd, sizeof subd, "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:dave\"}}", tx->url);
  char* jd1 = put_set(tx, iya_saml_event_uri("credential_change"), subd, "\"credential_type\":\"password\",\"change_type\":\"update\"", NULL, "", "");
  char subd2[320];
  snprintf(subd2, sizeof subd2, "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:dave\"},\"session\":{\"format\":\"opaque\",\"id\":\"IDP-D1\"}}", tx->url);
  char* jd2 = put_set(tx, iya_saml_event_uri("session_revoked"), subd2, NULL, NULL, "", "");
  for (int i = 0; !rc && i < 3; i++) {
    if (iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("throw poll", &err);
  }
  if (!rc && (!list_has(tx->acked, tx->acked_n, jd1) || !list_has(tx->acked, tx->acked_n, jd2))) rc = fail("throw ack");
  if (!rc && (list_has(tx->erred, tx->erred_n, jd1) || list_has(tx->erred, tx->erred_n, jd2))) rc = fail("throw erred");
  int handler_log = 0, end_log = 0;
  for (int i = 0; i < throwing.errors_n; i++) {
    if (contains(throwing.errors[i], "handler for") && contains(throwing.errors[i], "credential-change")) handler_log = 1;
    if (contains(throwing.errors[i], "onEndSessions threw")) end_log = 1;
  }
  if (!rc && (!handler_log || !end_log)) rc = fail("logs");
  iya_saml_receiver_free(receiver);
  free(jd1);
  free(jd2);

  Seen once;
  memset(&once, 0, sizeof once);
  pthread_mutex_init(&once.mu, NULL);
  receiver = iya_saml_receiver_new(tx->url, 0, on_end, &once, on_log, &once, &err);
  iya_saml_receiver_on(receiver, "*", on_event, &once);
  if (!rc && iya_saml_receiver_start(receiver, &err) != 0) rc = fail_err("once start", &err);
  if (receiver) iya_saml_receiver_stop(receiver);
  char sube[256];
  snprintf(sube, sizeof sube, "{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:erin\"}", tx->url);
  char* je = put_set(tx, iya_saml_event_uri("account_enabled"), sube, NULL, NULL, "", "");
  pthread_t threads[3];
  for (int i = 0; i < 3; i++) pthread_create(&threads[i], NULL, poll_thread, receiver);
  for (int i = 0; i < 3; i++) pthread_join(threads[i], NULL);
  if (!rc && iya_saml_receiver_poll(receiver, NULL, &err) != 0) rc = fail_err("once poll", &err);
  int count = 0;
  for (int i = 0; i < once.seen_n; i++)
    if (strcmp(once.seen_jti[i], je) == 0) count++;
  if (!rc && count != 1) rc = fail("handled twice");
  iya_saml_receiver_free(receiver);
  free(je);
  free(j1);
  free(j2);
  free(j3);
  free(jmail);
  pthread_mutex_destroy(&seen.mu);
  pthread_mutex_destroy(&forged_seen.mu);
  pthread_mutex_destroy(&throwing.mu);
  pthread_mutex_destroy(&once.mu);
  stop_tx(tx);
  return rc;
}

static int test_no_poll_delivery(void) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  Seen seen;
  memset(&seen, 0, sizeof seen);
  iya_saml_receiver* receiver = iya_saml_receiver_new("http://127.0.0.1:1", 0, on_end, &seen, on_log, &seen, &err);
  if (!receiver) return fail_err("new", &err);
  int rc = iya_saml_receiver_start(receiver, &err);
  int bad = rc == 0 || strcmp(err.code, "ssf") != 0;
  if (bad) printf("FAIL %s %s\n", err.code, err.message);
  iya_saml_receiver_free(receiver);
  return bad;
}

/* Plain http off loopback (#8). These run inside three registered tests
 * (TestReadsTheIdentityProviderFromItsMetadata,
 * TestRefusesAnArtifactFromAnotherIdentityProvider,
 * TestRefusesATransmitterWithoutPollDelivery) and by their own names when the
 * binary is run by hand. Each fetch (metadata, ArtifactResolve, the
 * transmitter) is refused before a connection is opened. http://example.com
 * names a host off this machine; http://0.0.0.0:<port> is not loopback either
 * but Linux delivers it to a socket on 127.0.0.1, so a listener there shows
 * whether the library opened a connection at all. */
typedef struct {
  int fd;
  int port;
} Listener;

static Listener listen_loopback(void) {
  Listener l = {-1, 0};
  l.fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(l.fd, (struct sockaddr*)&addr, sizeof addr);
  listen(l.fd, 4);
  socklen_t len = sizeof addr;
  getsockname(l.fd, (struct sockaddr*)&addr, &len);
  l.port = ntohs(addr.sin_port);
  return l;
}

/* 1 when a connection is waiting to be accepted. */
static int connection_waiting(Listener* l) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(l->fd, &fds);
  struct timeval tv = {0, 100000};
  return select(l->fd + 1, &fds, NULL, NULL, &tv) > 0;
}

static int refused_plain(const char* what, const iya_saml_error* err, const char* code, const char* host) {
  char want[128];
  snprintf(want, sizeof want, "http://%s is refused", host);
  if (strcmp(err->code, code) != 0 || !contains(err->message, want) || !contains(err->message, "use https")) {
    printf("FAIL %s: code %s want %s: %s\n", what, err->code, code, err->message);
    return 1;
  }
  return 0;
}

static char* url_config(const char* metadata_url) {
  char* key = json_quote(sp_key);
  char* cert = json_quote(sp_cert);
  char* meta = json_quote(metadata_url);
  size_t cap = strlen(key) + strlen(cert) + strlen(meta) + 512;
  char* out = malloc(cap);
  snprintf(out, cap, "{\"entityId\":\"%s\",\"acsUrl\":\"%s\",\"privateKey\":%s,\"certificate\":%s,\"idpMetadata\":%s}", kSp, kAcs, key, cert, meta);
  free(key);
  free(cert);
  free(meta);
  return out;
}

static int create_fails(const char* metadata_url, iya_saml_error* err) {
  char* json = url_config(metadata_url);
  memset(err, 0, sizeof *err);
  iya_saml_sp* sp = iya_saml_create(json, "", err);
  free(json);
  if (sp) {
    iya_saml_sp_free(sp);
    return 0;
  }
  return 1;
}

static int test_plain_metadata(void) {
  iya_saml_error err;
  if (!create_fails("http://example.com/saml2/metadata", &err)) return fail("example.com metadata accepted");
  if (refused_plain("example.com", &err, "metadata", "example.com")) return 1;
  Listener l = listen_loopback();
  char url[96];
  snprintf(url, sizeof url, "http://0.0.0.0:%d/saml2/metadata", l.port);
  int rc = 0;
  char host[32];
  snprintf(host, sizeof host, "0.0.0.0:%d", l.port);
  if (!create_fails(url, &err)) rc = fail("0.0.0.0 metadata accepted");
  if (!rc) rc = refused_plain("0.0.0.0", &err, "metadata", host);
  if (!rc && connection_waiting(&l)) rc = fail("a connection was opened");
  close(l.fd);
  /* Userinfo is never loopback, and never in the message. */
  if (!rc && !create_fails("http://alice:s3cret@localhost:1/m", &err)) rc = fail("userinfo accepted");
  if (!rc) rc = refused_plain("userinfo", &err, "metadata", "localhost:1");
  if (!rc && (contains(err.message, "s3cret") || contains(err.message, "alice"))) rc = fail("userinfo in the message");
  return rc;
}

static int artifact_refused(const char* ars_url, const char* host, Listener* l) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = must_sp(NULL, ars_url, &err);
  if (!sp) return fail_err("create", &err);
  char* artifact = artifact_for("");
  char* esc = uri_escape(artifact);
  char* url = malloc(strlen(esc) + 32);
  sprintf(url, "/saml/acs?SAMLart=%s", esc);
  char want[128];
  snprintf(want, sizeof want, "http://%s is refused", host);
  int rc = rejects(sp, "GET", url, NULL, "_r", "artifact", want);
  if (!rc && l && connection_waiting(l)) rc = fail("a connection was opened");
  free(url);
  free(esc);
  free(artifact);
  iya_saml_sp_free(sp);
  return rc;
}

static int test_plain_artifact(void) {
  if (artifact_refused("http://example.com/saml2/ars", "example.com", NULL)) return 1;
  Listener l = listen_loopback();
  char url[96];
  char host[32];
  snprintf(url, sizeof url, "http://0.0.0.0:%d/ars", l.port);
  snprintf(host, sizeof host, "0.0.0.0:%d", l.port);
  int rc = artifact_refused(url, host, &l);
  close(l.fd);
  return rc;
}

static int transmitter_refused(const char* transmitter, const char* host, Listener* l) {
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  Seen seen;
  memset(&seen, 0, sizeof seen);
  iya_saml_receiver* receiver = iya_saml_receiver_new(transmitter, 0, on_end, &seen, on_log, &seen, &err);
  if (!receiver) return fail_err("new", &err);
  int rc = iya_saml_receiver_start(receiver, &err) == 0 ? fail("the receiver started") : refused_plain("transmitter", &err, "ssf", host);
  if (!rc && l && connection_waiting(l)) rc = fail("a connection was opened");
  iya_saml_receiver_free(receiver);
  return rc;
}

static int test_plain_transmitter(void) {
  if (transmitter_refused("http://example.com", "example.com", NULL)) return 1;
  Listener l = listen_loopback();
  char url[96];
  char host[32];
  snprintf(url, sizeof url, "http://0.0.0.0:%d", l.port);
  snprintf(host, sizeof host, "0.0.0.0:%d", l.port);
  int rc = transmitter_refused(url, host, &l);
  close(l.fd);
  return rc;
}

/* Whitespace and control characters (#16), run inside
 * TestReadsTheIdentityProviderFromItsMetadata and by its own name. Every URL
 * below names the loopback listener, which plain http may reach: without the
 * refusal the library would connect to it (the WHATWG rules would also read
 * "local\nhost" as localhost). With it, each fetch is refused with its own
 * code, the message never repeats the URL, and nothing connects. */
static const char* kWhitespace = "whitespace or a control character";

static int refused_whitespace(const char* what, const iya_saml_error* err, const char* code) {
  if (strcmp(err->code, code) != 0 || !contains(err->message, kWhitespace) || contains(err->message, "127.0.0.1")) {
    printf("FAIL %s: code %s want %s: %s\n", what, err->code, code, err->message);
    return 1;
  }
  return 0;
}

static int test_whitespace_urls(void) {
  static const char* kInserts[] = {"\t", " ", "\n", "\r\n", "\x7f", "\x01", "\xc2\xa0", "\xc2\x85", "\xe2\x80\xa8", "\xe3\x80\x80"};
  Listener l = listen_loopback();
  int rc = 0;
  char url[128];
  iya_saml_error err;
  for (size_t i = 0; !rc && i < sizeof kInserts / sizeof kInserts[0]; i++) {
    snprintf(url, sizeof url, "http://127.0.0.1:%d/saml2/m%setadata", l.port, kInserts[i]);
    if (!create_fails(url, &err)) rc = fail("metadata with whitespace accepted");
    if (!rc) rc = refused_whitespace("metadata", &err, "metadata");
  }
  if (!rc) {
    snprintf(url, sizeof url, "http://local\nhost:%d/saml2/metadata", l.port);
    if (!create_fails(url, &err)) rc = fail("local\\nhost accepted");
    if (!rc) rc = refused_whitespace("host", &err, "metadata");
  }
  if (!rc) {
    snprintf(url, sizeof url, "https://127.0.0.1:%d/saml2/m\tetadata", l.port);
    if (!create_fails(url, &err)) rc = fail("https with a tab accepted");
    if (!rc) rc = refused_whitespace("https", &err, "metadata");
  }
  /* A Location in metadata, then the ArtifactResolve. */
  if (!rc) {
    snprintf(url, sizeof url, "http://127.0.0.1:%d/saml2/a rs", l.port);
    memset(&err, 0, sizeof err);
    iya_saml_sp* sp = must_sp(NULL, url, &err);
    if (!sp) rc = fail_err("create", &err);
    if (sp) {
      char* artifact = artifact_for("");
      char* esc = uri_escape(artifact);
      char* acs = malloc(strlen(esc) + 32);
      sprintf(acs, "/saml/acs?SAMLart=%s", esc);
      rc = rejects(sp, "GET", acs, NULL, "_r", "artifact", kWhitespace);
      free(acs);
      free(esc);
      free(artifact);
      iya_saml_sp_free(sp);
    }
  }
  /* The transmitter. */
  for (int k = 0; !rc && k < 2; k++) {
    snprintf(url, sizeof url, k == 0 ? "http://127.0.0.1:%d/s\tsf" : "http://127.0.0.1:%d/s\xc2\xa0sf", l.port);
    memset(&err, 0, sizeof err);
    Seen seen;
    memset(&seen, 0, sizeof seen);
    iya_saml_receiver* receiver = iya_saml_receiver_new(url, 0, on_end, &seen, on_log, &seen, &err);
    if (!receiver) {
      rc = fail_err("new", &err);
      break;
    }
    rc = iya_saml_receiver_start(receiver, &err) == 0 ? fail("the receiver started") : refused_whitespace("transmitter", &err, "ssf");
    iya_saml_receiver_free(receiver);
  }
  if (!rc && connection_waiting(&l)) rc = fail("a connection was opened");
  close(l.fd);
  return rc;
}

/* One GET answered with this IdP's metadata, on a loopback listener. */
typedef struct {
  Listener l;
  pthread_t thread;
  int served;
} MetaServer;

static void* meta_thread(void* arg) {
  MetaServer* m = arg;
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(m->l.fd, &fds);
  struct timeval tv = {10, 0};
  if (select(m->l.fd + 1, &fds, NULL, NULL, &tv) <= 0) return NULL;
  int client = accept(m->l.fd, NULL, NULL);
  if (client < 0) return NULL;
  char *method, *path, *body;
  char* raw = read_http(client, &method, &path, &body);
  char* meta = idp_metadata("");
  http_write(client, 200, "application/samlmetadata+xml", meta);
  m->served = 1;
  free(meta);
  free(method);
  free(path);
  free(body);
  free(raw);
  close(client);
  return NULL;
}

static int metadata_over(const char* host) {
  MetaServer m;
  memset(&m, 0, sizeof m);
  m.l = listen_loopback();
  pthread_create(&m.thread, NULL, meta_thread, &m);
  char url[96];
  snprintf(url, sizeof url, "http://%s:%d/saml2/metadata", host, m.l.port);
  char* json = url_config(url);
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  iya_saml_sp* sp = iya_saml_create(json, "", &err);
  free(json);
  int rc = 0;
  if (!sp) rc = fail_err(host, &err);
  else if (strcmp(iya_saml_idp_entity_id(sp), kIdp) != 0 || !m.served) rc = fail("metadata not read");
  iya_saml_sp_free(sp);
  pthread_join(m.thread, NULL);
  close(m.l.fd);
  return rc;
}

static int test_plain_loopback(void) {
  /* Plain http to loopback still works: 127.0.0.1 and localhost. */
  if (metadata_over("127.0.0.1")) return 1;
  if (metadata_over("localhost")) return 1;
  /* https is not touched by the rule: a name that does not resolve fails as a
   * connection failure, not as a refusal of plain http. */
  iya_saml_error err;
  if (!create_fails("https://idp.invalid/saml2/metadata", &err)) return fail("idp.invalid resolved");
  if (strcmp(err.code, "metadata") != 0 || contains(err.message, "is refused")) {
    printf("FAIL https: %s %s\n", err.code, err.message);
    return 1;
  }
  return 0;
}

typedef struct {
  Tx* tx;
  iya_saml_receiver* receiver;
  int start_done;
  int start_rc;
  int stop_done;
  iya_saml_error err;
} StopState;

static void* start_thread(void* arg) {
  StopState* state = arg;
  state->start_rc = iya_saml_receiver_start(state->receiver, &state->err);
  state->start_done = 1;
  return NULL;
}

static void* stop_thread(void* arg) {
  StopState* state = arg;
  iya_saml_receiver_stop(state->receiver);
  state->stop_done = 1;
  return NULL;
}

static int test_stop_waits(void) {
  Tx* tx = start_tx();
  tx->hold = 1;
  Seen seen;
  memset(&seen, 0, sizeof seen);
  iya_saml_error err;
  memset(&err, 0, sizeof err);
  StopState state;
  memset(&state, 0, sizeof state);
  state.tx = tx;
  state.receiver = iya_saml_receiver_new(tx->url, 60000, on_end, &seen, on_log, &seen, &err);
  if (!state.receiver) {
    stop_tx(tx);
    return fail_err("receiver", &err);
  }
  pthread_t starter;
  pthread_create(&starter, NULL, start_thread, &state);
  struct timespec deadline;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 5;
  pthread_mutex_lock(&tx->mu);
  while (!tx->entered_flag) {
    if (pthread_cond_timedwait(&tx->entered, &tx->mu, &deadline) == ETIMEDOUT) {
      pthread_mutex_unlock(&tx->mu);
      return fail("poll did not start");
    }
  }
  pthread_mutex_unlock(&tx->mu);
  pthread_t stopper;
  pthread_create(&stopper, NULL, stop_thread, &state);
  usleep(150000);
  if (state.stop_done) return fail("stop returned before the poll finished");
  pthread_mutex_lock(&tx->mu);
  tx->release_flag = 1;
  pthread_cond_broadcast(&tx->release);
  pthread_mutex_unlock(&tx->mu);
  for (int i = 0; i < 50 && !state.stop_done; i++) usleep(100000);
  if (!state.stop_done) return fail("stop did not return");
  pthread_join(stopper, NULL);
  pthread_join(starter, NULL);
  int rc = state.start_rc != 0 ? fail_err("start", &state.err) : 0;
  iya_saml_receiver_free(state.receiver);
  stop_tx(tx);
  return rc;
}

static int test_configure_script(void) {
  char dir[] = "/tmp/saml-cfg-XXXXXX";
  if (!mkdtemp(dir)) return fail("mkdtemp");
  char path[256];
  snprintf(path, sizeof path, "%s/saml.json", dir);
  FILE* file = fopen(path, "w");
  if (!file) return fail("write");
  fputs("{\"entityId\":\"http://localhost:3000/saml/metadata\",\"acsUrl\":\"http://localhost:3000/saml/acs\",\"privateKey\":\"generated/sp.key\",\"certificate\":\"generated/sp.crt\",\"idpMetadata\":\"generated/idp-metadata.xml\",\"idpCa\":\"generated/idp-ca.pem\"}\n", file);
  fclose(file);
  const char* script =
      "import importlib.util, json, sys\n"
      "from pathlib import Path\n"
      "spec = importlib.util.spec_from_file_location('configure_iya_sts', sys.argv[1])\n"
      "mod = importlib.util.module_from_spec(spec)\n"
      "spec.loader.exec_module(mod)\n"
      "folder = Path(sys.argv[2])\n"
      "raw = json.loads((folder / 'saml.json').read_text())\n"
      "with_ssf = folder / 'saml-ssf.json'\n"
      "with_ssf.write_text(json.dumps({**raw, 'ssf': {'transmitter': 'https://localhost:8081'}}))\n"
      "files = mod.files_of(str(with_ssf))\n"
      "assert files.ssf_transmitter == 'https://localhost:8081', files.ssf_transmitter\n"
      "calls = mod.ssf_calls(files, 'https://localhost:8081', 'PEM')\n"
      "paths = [call['path'].replace('https://localhost:8081/admin-api', '') for call in calls]\n"
      "assert paths == ['/applications/add', '/roles/add-member', '/tls/trust/add', '/applications/add-certificate'], paths\n"
      "assert calls[0]['body'] == {'application': 'http://localhost:3000/saml/metadata', 'attribute': 'oauthAllowedScope', 'value': 'ssf.manage'}\n"
      "assert calls[1]['body'] == {'role': 'SSF_MANAGE', 'kind': 'application', 'member': 'http://localhost:3000/saml/metadata'}\n"
      "assert any(call['path'].endswith('/applications/add-certificate') for call in mod.plan_for(files, 'https://localhost:8081', '', 'x'))\n"
      "plain = mod.files_of(str(folder / 'saml.json'))\n"
      "assert not any(call['path'].endswith('/applications/add-certificate') for call in mod.plan_for(plain, 'https://localhost:8081', '', 'x'))\n"
      "off = folder / 'saml-signals-off.json'\n"
      "off.write_text(json.dumps({**raw, 'signals': False, 'ssf': {'transmitter': 'https://localhost:8081'}}))\n"
      "files = mod.files_of(str(off))\n"
      "assert files.ssf_transmitter is None\n"
      "assert files.entity_id == 'http://localhost:3000/saml/metadata'\n"
      "import re\n"
      "def re_path(path):\n"
      "    return re.search(r'/applications/add$|/roles/add-member|/tls/trust/add|/applications/add-certificate', path) is not None\n"
      "assert not any(re_path(call['path']) for call in mod.plan_for(files, 'https://localhost:8081', '', 'x'))\n"
      "bare = folder / 'saml-signals-off-no-tx.json'\n"
      "bare.write_text(json.dumps({**raw, 'signals': False, 'ssf': {}}))\n"
      "assert mod.files_of(str(bare)).ssf_transmitter is None\n"
      "bad = folder / 'saml-signals-bad.json'\n"
      "bad.write_text(json.dumps({**raw, 'signals': 'no', 'ssf': {'transmitter': 'https://localhost:8081'}}))\n"
      "try:\n"
      "    mod.files_of(str(bad))\n"
      "except SystemExit as err:\n"
      "    assert 'signals must be true or false' in str(err)\n"
      "else:\n"
      "    raise SystemExit('signals no was accepted')\n";
  pid_t pid = fork();
  if (pid == 0) {
    execlp("python3", "python3", "-c", script, "scripts/configure_iya_sts.py", dir, (char*)NULL);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return fail("configure script");
  return 0;
}

static char* demo_binary;

// One HTTP/1.1 request to 127.0.0.1:port; the whole response (headers and body), or NULL.
static char* demo_request(int port, const char* method, const char* path, const char* headers, const char* body) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return NULL;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  if (connect(fd, (struct sockaddr*)&addr, sizeof addr) != 0) {
    close(fd);
    return NULL;
  }
  struct timeval tv = {10, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  size_t body_len = body ? strlen(body) : 0;
  size_t cap = strlen(path) + (headers ? strlen(headers) : 0) + body_len + 256;
  char* request = malloc(cap);
  int n = snprintf(request, cap, "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\nContent-Length: %zu\r\n%s\r\n%s", method, path, port, body_len,
                   headers ? headers : "", body ? body : "");
  send(fd, request, (size_t)n, MSG_NOSIGNAL);
  free(request);
  size_t len = 0;
  size_t room = 4096;
  char* out = malloc(room);
  for (;;) {
    if (len + 4096 > room) {
      room *= 2;
      out = realloc(out, room);
    }
    ssize_t got = recv(fd, out + len, 4095, 0);
    if (got <= 0) break;
    len += (size_t)got;
  }
  out[len] = '\0';
  close(fd);
  return out;
}

static const char* response_body(const char* response) {
  const char* split = response ? strstr(response, "\r\n\r\n") : NULL;
  return split ? split + 4 : "";
}

// The value of the first Set-Cookie for name, or "".
static void set_cookie_value(const char* response, const char* name, char* out, size_t cap) {
  out[0] = '\0';
  char needle[128];
  snprintf(needle, sizeof needle, "set-cookie: %s=", name);
  const char* at = response ? strcasestr(response, needle) : NULL;
  if (!at) return;
  at += strlen(needle);
  size_t n = 0;
  while (at[n] && at[n] != ';' && at[n] != '\r' && n + 1 < cap) {
    out[n] = at[n];
    n++;
  }
  out[n] = '\0';
}

static int free_port(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(fd, (struct sockaddr*)&addr, sizeof addr);
  socklen_t len = sizeof addr;
  getsockname(fd, (struct sockaddr*)&addr, &len);
  int port = ntohs(addr.sin_port);
  close(fd);
  return port;
}

static int test_live_status(void) {
  if (!demo_binary) return fail("the saml-demo path is required");
  char dir[] = "/tmp/saml-live-XXXXXX";
  if (!mkdtemp(dir)) return fail("mkdtemp");
  char path[256];
  snprintf(path, sizeof path, "%s/saml.json", dir);
  char* json = config_json("\"allowUnsolicited\":true", "");
  FILE* file = fopen(path, "w");
  if (!file) return fail("write");
  fputs(json, file);
  fclose(file);
  free(json);
  int port = free_port();
  pid_t pid = fork();
  if (pid == 0) {
    char port_text[16];
    snprintf(port_text, sizeof port_text, "%d", port);
    setenv("PORT", port_text, 1);
    setenv("SAML_CONFIG", path, 1);
    unsetenv("PUBLIC_URL");
    freopen("/dev/null", "w", stdout);
    execl(demo_binary, demo_binary, (char*)NULL);
    _exit(127);
  }
  int rc = 0;
  char* health = NULL;
  for (int i = 0; i < 100 && !(health && strstr(health, "\r\n\r\nok")); i++) {
    free(health);
    usleep(100000);
    health = demo_request(port, "GET", "/healthz", "", "");
  }
  if (!health || !strstr(health, "\r\n\r\nok")) rc = fail("the demo did not answer /healthz");
  free(health);
  char* before = rc ? NULL : demo_request(port, "GET", "/live-status", "", "");
  if (!rc && (!before || !strcasestr(before, "content-type: application/json") || !strcasestr(before, "cache-control: no-store"))) rc = fail(before ? before : "live-status");
  if (!rc && strcmp(response_body(before),
                    "{\"signedIn\":false,\"subject\":null,\"receiver\":\"not configured (no ssf block in the configuration file)\",\"events\":[]}") != 0)
    rc = fail(response_body(before));
  free(before);
  char* xml = NULL;
  if (!rc) {
    ResponseOpt opt = {0};
    opt.sign = 1;
    xml = response_xml(opt);
  }
  char* reply = NULL;
  if (!rc) {
    char* encoded = b64((const unsigned char*)xml, strlen(xml));
    char* escaped = uri_escape(encoded);
    size_t cap = strlen(escaped) + 32;
    char* form = malloc(cap);
    snprintf(form, cap, "SAMLResponse=%s", escaped);
    reply = demo_request(port, "POST", "/saml/acs", "Content-Type: application/x-www-form-urlencoded\r\n", form);
    free(form);
    free(escaped);
    free(encoded);
    if (!reply || strncmp(reply, "HTTP/1.1 303", 12) != 0) rc = fail(reply ? reply : "acs");
  }
  char sid[256] = "";
  if (!rc) {
    set_cookie_value(reply, "sid", sid, sizeof sid);
    if (!sid[0]) rc = fail("no sid cookie");
  }
  if (!rc) {
    char cookie[320];
    snprintf(cookie, sizeof cookie, "Cookie: sid=%s\r\n", sid);
    char* after = demo_request(port, "GET", "/live-status", cookie, "");
    const char* body = response_body(after);
    if (!contains(body, "\"signedIn\":true") || !contains(body, "\"subject\":\"alice-1234\"")) rc = fail(body);
    else if (contains(body, "Assertion") || contains(body, "SAMLResponse") || contains(body, "token") || contains(body, "_session1")) rc = fail(body);
    free(after);
    char* other = demo_request(port, "GET", "/live-status", "", "");
    if (!rc && !contains(response_body(other), "\"signedIn\":false")) rc = fail(response_body(other));
    free(other);
  }
  free(reply);
  free(xml);
  kill(pid, SIGTERM);
  int status = 0;
  waitpid(pid, &status, 0);
  unlink(path);
  rmdir(dir);
  return rc;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "test name required\n");
    return 2;
  }
  if (init_keys() != 0) return 1;
  const char* name = argv[1];
  if (argc > 2) demo_binary = argv[2];
  if (strcmp(name, "TestRefusesAConfigurationWithoutAKeyOrWithAnotherCertificate") == 0) return test_refuses_config();
  if (strcmp(name, "TestReadsTheIdentityProviderFromItsMetadata") == 0) return test_reads_idp() || test_plain_metadata() || test_plain_loopback() || test_whitespace_urls();
  if (strcmp(name, "TestWritesMetadataWithASignedRequestsKeyAndTheAcsOnAllThreeBindings") == 0) return test_metadata();
  if (strcmp(name, "TestOmitsSignalsUnlessItIsFalse") == 0) return test_omits_signals();
  if (strcmp(name, "TestRecordsSignalsFalseAndStillResolvesTheSamlFields") == 0) return test_signals_false();
  if (strcmp(name, "TestRefusesASignalsValueThatIsNotTrueOrFalse") == 0) return test_signals_bad();
  if (strcmp(name, "TestRedirectAuthnRequestIsDeflatedAndSigned") == 0) return test_redirect_authn();
  if (strcmp(name, "TestPostAuthnRequestIsAnEnvelopedSignatureInAForm") == 0) return test_post_authn();
  if (strcmp(name, "TestSubjectHintFollowsTheIssuerAndItsSignature") == 0) return test_subject_hint();
  if (strcmp(name, "TestRefusesARelayStateOver80Bytes") == 0) return test_relay_limit();
  if (strcmp(name, "TestSignedResponseAndSignedAssertion") == 0) return test_signed_both();
  if (strcmp(name, "TestAcceptsASignedAssertionInAnUnsignedResponse") == 0) return test_signed_assertion_only();
  if (strcmp(name, "TestRefusesAnUnsignedAssertionByDefault") == 0) return test_unsigned_assertion();
  if (strcmp(name, "TestRefusesAResponseWithNothingSigned") == 0) return test_nothing_signed();
  if (strcmp(name, "TestRefusesAnAssertionAlteredAfterItWasSigned") == 0) return test_altered();
  if (strcmp(name, "TestRefusesASignatureByAnotherKey") == 0) return test_other_key();
  if (strcmp(name, "TestIsNotFooledBySignatureWrapping") == 0) return test_wrapping();
  if (strcmp(name, "TestRefusesAResponseForAnotherAudienceAcsOrThatHasExpired") == 0) return test_audience_expiry();
  if (strcmp(name, "TestRefusesAnAnswerToAnotherRequestAndAnUnsolicitedOne") == 0) return test_in_response_to();
  if (strcmp(name, "TestRefusesTheSameAssertionTwice") == 0) return test_replay();
  if (strcmp(name, "TestReportsANonSuccessStatus") == 0) return test_status();
  if (strcmp(name, "TestRefusesADoctype") == 0) return test_doctype();
  if (strcmp(name, "TestDecryptsAnEncryptedAssertion") == 0) return test_decrypt();
  if (strcmp(name, "TestRefusesAPlaintextAssertionWhenEncryptionIsRequired") == 0) return test_require_encryption();
  if (strcmp(name, "TestRefusesAnEncryptedAssertionWhoseCiphertextWasAltered") == 0) return test_altered_cipher();
  if (strcmp(name, "TestDecryptsAnEncryptedAttribute") == 0) return test_encrypted_attribute();
  if (strcmp(name, "TestRedirectResponseVerifiesTheQuerySignature") == 0) return test_redirect_response();
  if (strcmp(name, "TestRefusesAQuerySignatureByAnotherKeyAndAChangedRelayState") == 0) return test_bad_query_sig();
  if (strcmp(name, "TestResolvesTheArtifact") == 0) return test_artifact();
  if (strcmp(name, "TestAcceptsTheArtifactOnAPostAndFailsWhenAlreadyUsed") == 0) return test_artifact_post();
  if (strcmp(name, "TestRefusesAnArtifactFromAnotherIdentityProvider") == 0) return test_foreign_artifact() || test_plain_artifact();
  if (strcmp(name, "TestRefusesARequestWithNoSamlMessage") == 0) return test_no_message();
  if (strcmp(name, "TestParseXMLHelperStaysAvailable") == 0) return test_parse_xml();
  if (strcmp(name, "TestVerifiesASetAgainstTheJwks") == 0) return test_jws();
  if (strcmp(name, "TestReadsComplexIssSubAndEmailSubjects") == 0) return test_subjects();
  if (strcmp(name, "TestNamesAllEightCaepAndFourteenRiscEventTypes") == 0) return test_event_names();
  if (strcmp(name, "TestSharedSignals") == 0) return test_shared();
  if (strcmp(name, "TestRefusesATransmitterWithoutPollDelivery") == 0) return test_no_poll_delivery() || test_plain_transmitter();
  if (strcmp(name, "TestStopWaitsForAnInFlightPoll") == 0) return test_stop_waits();
  if (strcmp(name, "TestRefusesPlainHttpMetadataOffLoopbackWithoutConnecting") == 0) return test_plain_metadata();
  if (strcmp(name, "TestRefusesPlainHttpArtifactResolutionOffLoopbackWithoutConnecting") == 0) return test_plain_artifact();
  if (strcmp(name, "TestRefusesPlainHttpTransmitterOffLoopbackWithoutConnecting") == 0) return test_plain_transmitter();
  if (strcmp(name, "TestAllowsPlainHttpToLoopbackAndLeavesHttpsAlone") == 0) return test_plain_loopback();
  if (strcmp(name, "TestRefusesAUrlWithWhitespaceOrAControlCharacterWithoutConnecting") == 0) return test_whitespace_urls();
  if (strcmp(name, "TestConfigureScriptSignals") == 0) return test_configure_script();
  if (strcmp(name, "TestLiveStatusReportsTheSignInWithoutTokens") == 0) return test_live_status();
  fprintf(stderr, "unknown test %s\n", name);
  return 2;
}
