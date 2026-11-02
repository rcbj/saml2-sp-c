# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libxml2-dev zlib1g-dev python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j

FROM build AS test
RUN ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libxml2 zlib1g ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/saml2-sp /usr/local/bin/saml2-sp
COPY --from=build /src/build/saml-demo /usr/local/bin/saml-demo
COPY demo demo
COPY scripts scripts
COPY README.md LICENSE VERSION ./
ENV PORT=3000
EXPOSE 3000
CMD ["saml-demo"]
