# saml2-sp

Server-side SAML 2.0 service provider with CAEP and RISC for C and C++. The protocol is implemented once, in C++17. The C header declares the same operations as `extern "C"`. Those functions are defined in this library and call the C++ classes. C callers and C++ callers link one library binary.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. Publishing is not set up.

## Call surfaces

C++ includes `iya/saml.hpp`. `iya::saml::ServiceProvider::create` reads a configuration document, `login` builds a signed `AuthnRequest`, and `acs` accepts the response. `SignalsReceiver` polls a Shared Signals transmitter.

C includes `iya_saml.h`. `iya_saml_create`, `iya_saml_login`, and `iya_saml_acs` are the same operations. A C failure prints the message once on stderr and returns an error. The C++ classes throw `std::runtime_error` with that message and do not log again.

## Configuration

`saml.json` keys are `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, `signals`, and `ssf`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder.

`signals` omitted or `true` keeps the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, does not start a receiver, and is stored as `signals: false`. Any other value is refused: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

`wantAssertionsSigned` defaults to refusing an unsigned assertion. Bindings are HTTP-Redirect, HTTP-POST, and HTTP-Artifact. Artifact resolution is a signed SOAP `ArtifactResolve`. Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Exclusive canonicalization is `http://www.w3.org/2001/10/xml-exc-c14n#`. Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. Content encryption is AES-GCM and AES-CBC with RSA-OAEP. A `DOCTYPE` is refused. RelayState on redirect is at most 80 bytes. Assertion identifiers are remembered so a response cannot be replayed. CAEP has eight event types and RISC has fourteen.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-c-demo \
  saml2-sp generate-keys --config demo/saml.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-c-demo \
  saml2-sp metadata --config demo/saml.json
```

`saml2-sp generate-keys` writes a self-signed RSA certificate. `saml2-sp metadata` writes the service-provider metadata.

## Shared Signals

`iya::saml::SignalsReceiver::create` discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. `stop` waits until a poll already running has finished. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`. The C equivalents are `iya_saml_receiver_new`, `iya_saml_receiver_start`, `iya_saml_receiver_poll`, and `iya_saml_receiver_stop`.

## Tests

```bash
docker build --target test .
```

The suite runs in a container. The `test` stage is not the default image. The last stage is the demo and does not run the suite.

Signatures and decryption use OpenSSL. Exclusive canonicalization uses libxml2. The JSON parser and the HTTP client are in this repository. The stub identity provider is in the test files. No live iya-sts. Keys are generated in the test.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, logout, and metadata. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS).

```sh
python scripts/configure_iya_sts.py --config demo/saml.json
```

The registrar is a host Python script. It calls the `saml2-sp` command for keys, metadata, and the identity-provider summary. The container `PORT` wins over the shell `PORT`.
