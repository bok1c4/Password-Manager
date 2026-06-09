# Builds the pwmgr CLI. Arch base because the app needs libpqxx 8.x (C++20),
# which matches the upstream dev environment.
FROM archlinux:latest

# Runtime + build deps. base-devel pulls gcc/make/pkgconf; the rest are libs and
# the gpg/pinentry binaries gpgme shells out to at runtime.
RUN pacman -Syu --noconfirm \
        gcc make pkgconf git \
        libpqxx postgresql-libs openssl gpgme \
        gnupg pinentry \
    && pacman -Scc --noconfirm

WORKDIR /app
COPY . .

# Build the CLI (and the test runner). build/make/pwmgr is the binary.
RUN make

# Config is resolved from this absolute path; mount your config there.
ENV PWMGR_CONFIG=/config/config.json

ENTRYPOINT ["./build/make/pwmgr"]
