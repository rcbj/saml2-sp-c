/* SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC */
/* SPDX-License-Identifier: MIT */

#ifndef IYA_SAML_H
#define IYA_SAML_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iya_saml_sp iya_saml_sp;
typedef struct iya_saml_receiver iya_saml_receiver;

typedef struct iya_saml_error {
  int failed;
  char code[64];
  char message[4096];
  char status_code[512];
  char status_subcode[512];
  char status_message[1024];
} iya_saml_error;

typedef struct iya_saml_login_options {
  const char* relay_state; /* NULL omits RelayState */
  int force_authn;
  int passive;
  const char* subject_hint; /* NULL omits the subject */
  const char* subject_hint_format;
  const char* request_binding; /* NULL uses the configuration */
  const char* response_binding;
  const char* nonce;
} iya_saml_login_options;

typedef struct iya_saml_login_request {
  char* id;
  char* binding;
  char* response_binding;
  char* url;
  char* xml;
  char* html;
  char* saml_request;
  char* relay_state;
} iya_saml_login_request;

typedef struct iya_saml_acs_result {
  char* name_id;
  char* name_id_format;
  char* session_index;
  char* authn_context;
  char* binding;
  char* relay_state; /* NULL if the binding carried none */
  char* in_response_to; /* NULL if the response omitted it */
  int encrypted;
  char* assertion_id;
  char* issuer;
  int attr_count;
  char** attr_name;
  char** attr_values;
  char** attr_friendly;
} iya_saml_acs_result;

typedef struct iya_saml_event {
  const char* type;
  const char* jti;
  int ended;
  const char* const* sessions;
  int session_count;
  const char* person;
  const char* email;
  const char* idp_session;
} iya_saml_event;

typedef int (*iya_saml_end_fn)(const char* const* ids, int count, const iya_saml_event* event, void* user, char* err,
                               size_t err_cap);
typedef int (*iya_saml_handler_fn)(const iya_saml_event* event, void* user, char* err, size_t err_cap);
typedef void (*iya_saml_log_fn)(const char* level, const char* message, void* user);

/* Returns NULL and fills err on failure. Prints the message once. */
iya_saml_sp* iya_saml_create(const char* config_json, const char* base_dir, iya_saml_error* err);
void iya_saml_sp_free(iya_saml_sp* sp);

const char* iya_saml_entity_id(const iya_saml_sp* sp);
const char* iya_saml_acs_url(const iya_saml_sp* sp);
const char* iya_saml_request_binding(const iya_saml_sp* sp);
const char* iya_saml_response_binding(const iya_saml_sp* sp);
int iya_saml_want_assertions_signed(const iya_saml_sp* sp);
int iya_saml_want_assertions_encrypted(const iya_saml_sp* sp);
int iya_saml_allow_unsolicited(const iya_saml_sp* sp);
long long iya_saml_clock_skew_ms(const iya_saml_sp* sp);
int iya_saml_has_signals(const iya_saml_sp* sp);
int iya_saml_signals_value(const iya_saml_sp* sp);
const char* iya_saml_idp_entity_id(const iya_saml_sp* sp);
const char* iya_saml_idp_sso(const iya_saml_sp* sp, const char* binding);
int iya_saml_idp_certificate_count(const iya_saml_sp* sp);

int iya_saml_metadata(const iya_saml_sp* sp, char** out, iya_saml_error* err);
int iya_saml_login(iya_saml_sp* sp, const iya_saml_login_options* options, iya_saml_login_request* out,
                   iya_saml_error* err);
void iya_saml_login_request_free(iya_saml_login_request* request);

/* body NULL is no body. A body starting with '{' is a JSON object of strings; otherwise it is form-urlencoded. */
int iya_saml_acs(iya_saml_sp* sp, const char* method, const char* raw_url, const char* body, const char* const* request_ids,
                 int request_id_count, iya_saml_acs_result* out, iya_saml_error* err);
void iya_saml_login_free(iya_saml_acs_result* login);

int iya_saml_create_key_pair(const char* common_name, int days, int bits, char** key_pem, char** cert_pem,
                             iya_saml_error* err);
int iya_saml_sign_xml(const char* xml, const char* element_id, const char* key_pem, const char* cert_pem, char** out,
                      iya_saml_error* err);
int iya_saml_signature_verifies(const char* xml, const char* cert_pem, iya_saml_error* err);
int iya_saml_xml_well_formed(const char* xml);

/* signature_ok is 0 or 1. A bad signature is not an error return. */
int iya_saml_read_artifact_resolve(const char* xml, const char* cert_pem, char* id, size_t id_cap, char* artifact,
                                   size_t artifact_cap, int* signature_ok);

int iya_saml_caep_event_count(void);
int iya_saml_risc_event_count(void);
const char* iya_saml_event_uri(const char* name);
int iya_saml_subject(const char* sub_json, const char* issuer, char* person, size_t person_cap, char* email,
                     size_t email_cap, char* idp_session, size_t idp_cap, iya_saml_error* err);
int iya_saml_verify_jws(const char* token, const char* keys_json, char** payload_json, iya_saml_error* err);

iya_saml_receiver* iya_saml_receiver_new(const char* transmitter, int poll_interval_ms, iya_saml_end_fn on_end,
                                         void* user, iya_saml_log_fn log, void* log_user, iya_saml_error* err);
void iya_saml_receiver_free(iya_saml_receiver* receiver);
void iya_saml_receiver_on(iya_saml_receiver* receiver, const char* event_type, iya_saml_handler_fn fn, void* user);
void iya_saml_receiver_track(iya_saml_receiver* receiver, const char* local_id, const char* person,
                             const char* email, const char* idp_session);
int iya_saml_receiver_start(iya_saml_receiver* receiver, iya_saml_error* err);
void iya_saml_receiver_stop(iya_saml_receiver* receiver);
int iya_saml_receiver_poll(iya_saml_receiver* receiver, int* more, iya_saml_error* err);
int iya_saml_receiver_stream_id(const iya_saml_receiver* receiver, char* buf, size_t cap);
int iya_saml_receiver_sessions_for_person(const iya_saml_receiver* receiver, const char* person, char* buf, size_t cap);

void iya_saml_string_free(char* value);

#ifdef __cplusplus
}
#endif

#endif
