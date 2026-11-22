# MinIO over HTTPS with a self-signed certificate: pgBackRest talks to S3
# only over TLS. Morche and test-pitr reach it at https://127.0.0.1:9120.
FROM alpine:3.22 AS certs
RUN apk add --no-cache openssl \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=test-minio-tls' \
      -addext 'subjectAltName=DNS:test-minio-tls,DNS:localhost,IP:127.0.0.1' \
      -keyout /private.key -out /public.crt
FROM minio/minio:RELEASE.2025-09-07T16-13-09Z
COPY --from=certs /private.key /public.crt /root/.minio/certs/
