ARG BIN_IMAGE=ghcr.io/olidacombe/tpm-luks-dyn

FROM olidacombe/tpm-luks-ci AS base

WORKDIR /test
RUN mkdir bin

RUN git clone --depth 1 --branch v1.8.0 https://github.com/bats-core/bats-core.git bats
RUN mkdir test_helper
RUN git clone --depth 1 --branch v0.3.0 https://github.com/bats-core/bats-support.git test_helper/bats-support
RUN git clone --depth 1 --branch v2.0.0 https://github.com/bats-core/bats-assert.git test_helper/bats-assert
RUN git clone --depth 1 --branch v0.2.0 https://github.com/ztombol/bats-file.git test_helper/bats-file

FROM ${BIN_IMAGE} AS bin

FROM base AS test

COPY --from=bin /tpm-luks bin/

COPY . .

CMD ["bats/bin/bats", "--tap", "test.bats"]
