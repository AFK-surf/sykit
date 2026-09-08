# Canonical compiler host architecture is fixed as well as the image and apt
# snapshot. ARM hosts need Docker's amd64 emulation (Docker Desktop includes it).
FROM --platform=linux/amd64 docker.io/library/ubuntu@sha256:98ff7968124952e719a8a69bb3cccdd217f5fe758108ac4f21ad22e1df44d237 AS build
COPY toolchain/snapshot-ca.pem /etc/ssl/certs/ca-certificates.crt
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20260901T000000Z noble main universe\ndeb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20260901T000000Z noble-updates main universe\ndeb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/20260901T000000Z noble-security main universe\n' > /etc/apt/sources.list \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang-18 \
    && rm -rf /var/lib/apt/lists/*
ENV LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
WORKDIR /build
COPY include/ include/
COPY src/ src/
COPY scripts/compile.sh scripts/compile.sh
RUN sh scripts/compile.sh /out

FROM --platform=linux/amd64 scratch AS artifacts
COPY --from=build /out/ /artifacts/
