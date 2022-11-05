FROM alpine:latest AS build-base

RUN apk add --no-cache \
    alpine-sdk \
    autoconf \
    autoconf-archive \
    automake \
    bash \
    curl \
    cmake \
    g++ \
    gcc \
    git \
    iproute2 \
    libaio-dev \
    libtool \
    linux-headers \
    m4 \
    make \
    pkgconfig \
    popt-dev \
    util-linux-dev \
    xz
    
RUN mkdir /workdir
WORKDIR /libworkdir

### OpenSSL
ENV \
    OPENSSL_DIR="/usr/local/ssl" \
    OPENSSL_VER="1.1.1q"
RUN curl -sL https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz | tar xz

RUN cd openssl-${OPENSSL_VER} && \
    ./Configure \
    --openssldir=${OPENSSL_DIR} \
    --prefix=${OPENSSL_DIR} \
    no-shared \
    no-async \
    linux-x86_64 \
    && \
    make depend && make -j$(nproc) && make install_sw

ENV OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include" OPENSSL_LIBS="-L${OPENSSL_DIR}/lib -lcrypto"

### JSON-C
ENV JSON_C_VER="0.16"

RUN curl -sL https://s3.amazonaws.com/json-c_releases/releases/json-c-${JSON_C_VER}-nodoc.tar.gz | tar zx

RUN cd json-c-${JSON_C_VER} && \
    sed -i 's/add_subdirectory(doc)//' CMakeLists.txt && \
    mkdir build && \
    cd build && \
    cmake \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      .. && \
    make all install

### libdevicemapper
ENV LVM2_VER="2.02"

RUN git clone -b stable-$LVM2_VER --single-branch https://github.com/lvmteam/lvm2.git lvm2-$LVM2_VER

RUN cd lvm2-$LVM2_VER && \
    ./configure \
    --enable-static_link \
    --prefix=/usr/local \
    && \
    make install_device-mapper

### Cryptsetup
ENV CRYPTSETUP_VER="2.5.0"

RUN curl -sL https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/cryptsetup-${CRYPTSETUP_VER}.tar.xz | tar Jx

RUN cd cryptsetup-${CRYPTSETUP_VER} && \
    OPENSSL_STATIC_CFLAGS="$OPENSSL_CFLAGS" OPENSSL_STATIC_LIBS="$OPENSSL_LIBS" \
    ./configure \
    --disable-asciidoc \
    --disable-blkid \
    --disable-cryptsetup \
    --disable-keyring \
    --disable-nls \
    --disable-shared \
    --disable-ssh-token \
    --enable-static \
    --disable-udev \
    --prefix=/usr/local \
    && \
    make && make install
    # --disable-shared \

FROM build-base AS rust

### TPM2 TSS
ENV TPM2_TSS_VER="3.2.0"
RUN curl -sL https://github.com/tpm2-software/tpm2-tss/archive/refs/tags/${TPM2_TSS_VER}.tar.gz | tar xz

# Hack in the release version so pkg-config will work
RUN cd tpm2-tss-$TPM2_TSS_VER && \
    sed -i "/AC_INIT/"'!'"b;n;c\[${TPM2_TSS_VER}\]," configure.ac

ARG TPM_LUKS_BUILD_STATIC_TCTI=device

RUN cd tpm2-tss-$TPM2_TSS_VER && \
    ./bootstrap && \
    CRYPTO_CFLAGS="$OPENSSL_CFLAGS" CRYPTO_LIBS="$OPENSSL_LIBS" \
    ./configure \
    --disable-doxygen-doc \
    --disable-fapi \
    --enable-nodl \
    --disable-shared \
    --enable-static \
    $( for t in device swtpm mssim; do \
      echo -n --$( [ "${TPM_LUKS_BUILD_STATIC_TCTI}" = "$t" ] && echo en || echo dis )able-tcti-$t\ ; \
    done ) \
    && \
    make -j$(nproc) && \
    make install


### Rust
# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# .cargo/bin in PATH is needed for running cargo, rustup etc.
ENV PATH=/root/.cargo/bin:$PATH

RUN cargo install cargo-chef

ENV \
    PKG_CONFIG_ALL_STATIC=true \
    RUSTFLAGS="-C relocation-model=static" \
    TPM_LUKS_BUILD_STATIC=1 \
    TPM_LUKS_BUILD_STATIC_TCTI=${TPM_LUKS_BUILD_STATIC_TCTI} \
    TSS2_SYS_DYNAMIC=0 \
    TSS2_SYS_STATIC=1

WORKDIR /workdir

FROM rust AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust AS builder
COPY --from=planner /workdir/recipe.json recipe.json
RUN cargo chef cook --target x86_64-unknown-linux-musl --recipe-path recipe.json

COPY . .
RUN cargo build --release --target=x86_64-unknown-linux-musl

FROM scratch AS binary

COPY --from=builder /workdir/target/x86_64-unknown-linux-musl/release/tpm-luks .
