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

Signatures and decryption use OpenSSL. Exclusive canonicalization uses libxml2. The JSON parser and the HTTP client are in this repository. The stub identity provider is in the test files. Keys are generated in the test. `tests/trust.c` serves HTTPS from a four-certificate chain shaped like iya-sts's and checks that the whole `idpCa` chain file is the trust store (the leaf alone is refused, and so is a forged leaf followed by the real CA certificates), that the host name is verified, and that `scripts/trust_chain.py` writes the whole chain.

## Live iya-sts test and the nightly suite

```bash
python3 scripts/live_iya_sts.py
```

The script starts the latest `main` of iya-sts in a container (memory mode, no persistence, no clustering), registers the demo with it, signs in through the demo, emits CAEP `credential-change` and then `session-revoked`, and requires the demo's `GET /live-status` to show both, the second one with the local session ended. It prints JSON ending in `"ok": true`. `IYA_STS_URL` uses an iya-sts that is already running (and does not stop it), `IYA_STS_IMAGE` starts a fresh container from that image, and otherwise iya-sts `main` is cloned and built. `LIVE_STS_PORT` (default 18530) and `LIVE_DEMO_PORT` (default 18630) are the host ports. The library, the demo and the registrar build and run only in containers; the script needs the host's `python3` (standard library) and Docker. Always run it against a fresh iya-sts: a second run against an already-registered service provider is not supported.

`GET /live-status` answers `{"signedIn", "subject", "receiver", "events": [{"type", "jti"}]}` and never a token or an assertion. iya-sts `main` may put the assertion id in `SessionIndex`, so a `session-revoked` event can match no tracked session; the demo then ends its one local session and untracks it (demo code, not the library).

`.github/workflows/nightly.yml` runs the unit suite and the live script every day at 07:58 UTC (`58 7 * * *`), and on demand. Push and pull-request CI stays in `tests.yml`.

## The iya-sts trust chain (`idpCa`)

`idpCa` (demo default `file:generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain presented in the TLS handshake when that is missing. It prints the path, the anchor's subject and its SHA-256. `python3 scripts/trust_chain.py --idp <url>` does only that step.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (created mode 0600) and prints only that path. No line it or the live script prints carries anything derived from a password or secret.

The library loads every PEM block of `idpCa` into its OpenSSL trust store, so the path ends at the self-signed Root, and it verifies that the listener's certificate names the host in the URL: a DNS name against a DNS SAN, an IP literal (such as `127.0.0.1`) against an IP SAN. A certificate that chains to the trusted root but does not name the host is refused. This applies to the metadata fetch, artifact resolution and the Shared Signals receiver.

The demo image build copies `demo/` after compiling, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`, so the image carries the chain at `/app/demo/generated/idp-ca.pem` with no bind mount. Keys, secrets and metadata stay out of the image. A build before the install script has run still succeeds; the image then has no chain. Rebuild the image after re-running the install script against a different iya-sts.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. `GET /live-status` reports the sign-in and the accepted Shared Signals events as JSON, without tokens or assertions. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, logout, and metadata. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS).

```sh
python scripts/configure_iya_sts.py --config demo/saml.json
```

The registrar is a standard-library Python script. It calls the `saml2-sp` command for keys, metadata, and the identity-provider summary, so run it where that command is on `PATH`, such as inside the demo image (which has `python3`). It writes iya-sts's listener CA trust chain where `idpCa` names it (see above); rebuild the demo image afterwards. The container `PORT` wins over the shell `PORT`.
