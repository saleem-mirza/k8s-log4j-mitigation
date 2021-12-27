FROM rust:latest AS builder
RUN apt update -y && apt install openssl -y

COPY . /build_dir
RUN cd /build_dir && cargo install --path .

FROM debian:buster-slim
RUN apt update -y \
    && apt install openssl -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt \
    && mkdir /app /certs

VOLUME ["/certs"]

COPY --from=builder /build_dir/certs/ /certs
COPY --from=builder /usr/local/cargo/bin/log4j-mutating-webhook /app/

ENTRYPOINT [ "/app/log4j-mutating-webhook" ]

EXPOSE 443
CMD [ "--key", "/certs/tls.key", "--cert", "/certs/tls.crt" ]
