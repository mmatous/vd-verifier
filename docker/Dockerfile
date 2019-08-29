FROM rust:latest

ENV HOST_ARCH=x86_64-w64-mingw32
ENV TARGET_TOOLCHAIN=x86_64-pc-windows-gnu

RUN apt-get -yy update && \
    apt-get -yy install mingw-w64 libclang1 && \
    rustup self update && \
    rustup install stable-x86_64-unknown-linux-gnu && \
    rustup default stable-x86_64-unknown-linux-gnu && \
    rustup target add ${TARGET_TOOLCHAIN}

ENV PKG_CONFIG_ALLOW_CROSS=1 \
    PKG_CONFIG_PATH=/usr/${HOST_ARCH}/lib/pkgconfig \
	GMP_VERSION=6.1.2 \
	NETTLE_VERSION=3.5.1

RUN cd /tmp && \
    wget https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.bz2 && \
    tar xvf gmp-${GMP_VERSION}.tar.bz2 && \
    cd gmp-${GMP_VERSION} && \
    AR="${HOST_ARCH}-ar" \
    AS="${HOST_ARCH}-gcc" \
    CC="${HOST_ARCH}-gcc" \
    CXX="${HOST_ARCH}-g++" \
    LD="${HOST_ARCH}-ld" \
    STRIP="${HOST_ARCH}-strip" ./configure --host=${HOST_ARCH} --prefix=/usr/${HOST_ARCH} && \
    make -j14 && make install

RUN cd /tmp && \
    wget https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_VERSION}.tar.gz && \
    tar xvf nettle-${NETTLE_VERSION}.tar.gz && \
    cd nettle-${NETTLE_VERSION} && \
    AR="${HOST_ARCH}-ar" \
    AS="${HOST_ARCH}-gcc" \
    CC="${HOST_ARCH}-gcc" \
    CXX="${HOST_ARCH}-g++" \
    LD="${HOST_ARCH}-ld" \
    STRIP="${HOST_ARCH}-strip" ./configure --host=${HOST_ARCH} --prefix=/usr/${HOST_ARCH} \
      --with-lib-path=/usr/${HOST_ARCH}/lib \
      --with-include-path=/usr/${HOST_ARCH}/include && \
    make -j14 && make install

# prevent linking errors, https://github.com/rust-lang/rust/issues/48272#issuecomment-429596397
RUN cp /usr/${HOST_ARCH}/lib/crt2.o /usr/local/rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/${TARGET_TOOLCHAIN}/lib/.
