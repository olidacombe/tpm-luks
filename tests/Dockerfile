ARG BIN_IMAGE=ghcr.io/olidacombe/tpm-luks
FROM ${BIN_IMAGE} AS bin

FROM alpine:latest AS test

RUN apk add --no-cache \
    bash \
    cryptsetup \
    git

RUN ls /

WORKDIR /test

RUN mkdir bin

COPY --from=bin /tpm-luks bin/

RUN git clone --depth 1 --branch v1.8.0 https://github.com/bats-core/bats-core.git bats
RUN mkdir test_helper
RUN git clone --depth 1 --branch v0.3.0 https://github.com/bats-core/bats-support.git test_helper/bats-support
RUN git clone --depth 1 --branch v2.0.0 https://github.com/bats-core/bats-assert.git test_helper/bats-assert
RUN git clone --depth 1 --branch v0.2.0 https://github.com/ztombol/bats-file.git test_helper/bats-file

COPY . .

CMD ["bats/bin/bats", "--tap", "test.bats"]
