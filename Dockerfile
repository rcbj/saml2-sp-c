# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libxml2-dev zlib1g-dev python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in demo/ does not
# rebuild the binaries.
COPY CMakeLists.txt VERSION ./
COPY cmake cmake
COPY include include
COPY src src
COPY tests tests
COPY scripts scripts
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

FROM build AS test
RUN ctest --test-dir build --output-on-failure
# The installed package, static and shared, consumed through find_package.
RUN sh tests/package/check.sh iya_saml iya_saml IYA_SAML

FROM debian:bookworm-slim
# python3 and openssl run scripts/configure_iya_sts.py inside this image, where
# the saml2-sp command makes the keys and the metadata.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libxml2 zlib1g ca-certificates openssl python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/saml2-sp /usr/local/bin/saml2-sp
COPY --from=build /src/build/saml-demo /usr/local/bin/saml-demo
COPY scripts scripts
COPY README.md LICENSE VERSION ./
# demo/ comes after the build. .dockerignore admits one file of demo/generated:
# idp-ca.pem, the iya-sts listener CA trust chain scripts/configure_iya_sts.py
# writes where idpCa names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem; when it does not (a fresh clone, CI), the
# directory carries nothing from demo/generated and the build still succeeds.
# Keys and metadata never enter the image.
COPY demo demo
ENV PORT=3000
EXPOSE 3000
CMD ["saml-demo"]
