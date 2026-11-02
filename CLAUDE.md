# saml2-sp

C and C++ service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. One implementation, in C++17. C and C++ call the same library. Version 0.1.0. MIT. `develop` and `main` are one commit. Publishing is not set up.

## One implementation

Protocol code lives in `src/*.cpp`. `include/iya/saml.hpp` is the C++ surface (`ServiceProvider`, `SignalsReceiver`). `include/iya_saml.h` declares the same operations as `extern "C"`. The C functions are defined in this library and call the C++ classes. They are the C ABI, not a second protocol stack. Do not wrap another language port.

C functions print a failure once with `fprintf(stderr)` and return an error. C++ throws `std::runtime_error` with that message and does not log again.

## Usage

`ServiceProvider::create` or `iya_saml_create`, then login and ACS. JSON keys are `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, `signals`, and `ssf`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean fails with `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Exclusive canonicalization is `http://www.w3.org/2001/10/xml-exc-c14n#`. Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `wantAssertionsSigned` defaults to refusing an unsigned assertion. `saml2-sp generate-keys` writes a self-signed RSA certificate. `saml2-sp metadata` writes service-provider metadata.

OpenSSL signs, verifies, and decrypts (RSA-SHA256, AES-GCM, AES-CBC, RSA-OAEP, TLS). libxml2 parses XML and performs exclusive canonicalization. The JSON parser and the HTTP/1.1 client are in this repository.

## Tests

```bash
docker build --target test .
```

The named `test` stage runs `ctest` and is not the default image. The last stage is the demo and does not run the suite. GitHub Actions uses `docker build --target test .`. Do not compile this library on the host. The test image includes python3 so the registrar checks can run. `scripts/configure_iya_sts.py` is standard-library Python and must not invoke another language toolchain; it needs the `saml2-sp` command, so the live driver runs it inside the demo image (which has `python3` and `openssl`).

Signatures and decryption are real. The stub identity provider signs with this library's exclusive canonicalization and is created inside the tests. `tests/trust.c` (target `saml_trust_tests`) serves HTTPS from a four-certificate chain shaped like iya-sts's and checks that the whole `idpCa` chain file is the trust store (the leaf alone and a forged leaf before the real CA certificates are refused), that the host name is verified (right chain, wrong name refused; DNS name and `127.0.0.1` via an IP SAN accepted), and that `scripts/trust_chain.py` writes the whole chain from `GET /tls/server-certificate` and from the handshake. `TestLiveStatusReportsTheSignInWithoutTokens` runs the `saml-demo` binary.

## Live test and nightly

`python3 scripts/live_iya_sts.py` (host stdlib python3 and Docker; never CMake on the host) starts a fresh iya-sts `main` in memory mode as container `iya-sts-live-saml2-sp-c` on `LIVE_STS_PORT` (default 18530), copies the checkout to a scratch build context, builds the demo image, runs `scripts/configure_iya_sts.py` inside it as the host user on the host network (key pair, metadata, trust chain into the context's `demo/generated`), rebuilds the image (which bakes the chain in), checks the image's chain equals the saved one, runs `saml2-sp-c-live-demo` with `--network host` on `LIVE_DEMO_PORT` (default 18630) mounting only `sp.key`, `sp.crt` and `idp-metadata.xml`, signs in through `/authn-api`, emits `credential-change` then `session-revoked`, and checks `GET /live-status`. `IYA_STS_URL` and `IYA_STS_IMAGE` select an existing iya-sts or image. It never binds 3000, 8081 or 18481-18495. Secrets reach docker as `-e NAME`. Always against a fresh iya-sts: a second run against an already-registered service provider is not supported. `.github/workflows/nightly.yml` runs the unit image and the live script at 07:58 UTC (`58 7 * * *`).

`/live-status` is `{signedIn, subject, receiver, events: [{type, jti}]}`, never tokens. When `session-revoked` matched no tracked session (iya-sts `main` may put the assertion id in `SessionIndex`), the demo (`start_receiver` in `src/demo_main.cpp`, not the library) ends its one local session and untracks it.

## idpCa, the iya-sts trust chain

`idpCa` (demo default `file:generated/idp-ca.pem`) is iya-sts's listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain on every run via `scripts/trust_chain.py` (`GET /tls/server-certificate`, falling back to the handshake) and prints the path, anchor subject and SHA-256. `src/http.cpp` loads every PEM block as an anchor and verifies the host name (`SSL_set1_host`, or `X509_VERIFY_PARAM_set1_ip_asc` for an IP literal, which gets no SNI); there is no pinning shortcut. The build stage compiles from `CMakeLists.txt`, `VERSION`, `include`, `src`, `tests`, `scripts`; the demo stage then runs `COPY demo demo`; `.dockerignore` excludes `demo/generated/*` except `idp-ca.pem`, so the image carries the chain and no keys, and a build without it still succeeds. Rebuild the demo image after re-running the install script against a different iya-sts.

## Layout

`include/iya_saml.h`, `include/iya/saml.hpp`, `src/*.cpp`, CLI target `saml2-sp`, demo binary `saml-demo`, `scripts/configure_iya_sts.py`, `scripts/trust_chain.py`, `scripts/live_iya_sts.py`, `.github/workflows/nightly.yml`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-c-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. `GET /healthz` returns body `ok`.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok`. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, logout, metadata, and `GET /live-status`. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `stop` waits for an in-flight poll. CAEP has eight event types and RISC has fourteen. `scripts/configure_iya_sts.py` registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. Run it with `python scripts/configure_iya_sts.py --config demo/saml.json`. The container `PORT` wins over the shell `PORT` at registration.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-c-demo \
  saml2-sp generate-keys --config demo/saml.json
```
