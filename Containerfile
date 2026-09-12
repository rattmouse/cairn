# The image cairn's tests run in, locally and in CI.
#
# Nothing in cairn needs a container to run — invariant 1 says the tool
# installs with nothing but git, and that stays true. This image exists so
# the test suite runs against a known-empty machine: a fresh Debian with
# python3, git, openssl and bash and not one thing more. If a test ever
# starts depending on something that happens to be installed on a laptop,
# this is what catches it.
#
#     podman build -t cairn-ci .
#     podman run --rm cairn-ci
#
FROM docker.io/library/debian:stable-slim

# python3      — the server and the tests
# git          — invariant 1's one dependency; every save is a commit
# openssl      — --tls generates the self-signed cert with it
# ca-certificates — so the TLS tests have a trust store to compare against
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 git openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The tests start real servers, write real files and run a real shell through
# a pty. None of that wants root, and running as a user is closer to how
# anyone actually runs cairn.
RUN useradd --create-home --shell /bin/bash cairn

# Bytecode would land in a root-owned /src and be silently dropped anyway.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /src
COPY . /src
USER cairn

CMD ["python3", "tests/test_server.py"]
