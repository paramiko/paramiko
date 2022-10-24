# Convenience tool for testing a 32-bit related security flaw. May be
# generalized in future to be more useful; until then, it is NOT
# officially supported but purely a maintainer-facing artifact.

FROM --platform=i386 i386/alpine:3.15

RUN apk add openssl-dev python3-dev libffi-dev make cargo

RUN python3 -m venv env
RUN env/bin/pip install -U pip
