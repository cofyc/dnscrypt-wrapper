# CHANGELOG

## Table of Contents

* [v0.4.2](#v042)
* [v0.4.1](#v041)
* [v0.4.0](#v040)
* [v0.3.0](#v030)
* [v0.2.2](#v022)
* [v0.2.1](#v021)
* [v0.2.0](#v020)

## v0.4.2

- Log level of "suspicious query" changed to debug

## v0.4.1

- find_cert() should search in all certs, fixes #139.
- filter_signed_certs() should converts serial to uint32_t before comparison.
- --cert-file-expire-days supports 'd', 'h', 'm', 's' suffixes

## v0.4.0

- Use sodium_malloc() for the DNS query/response buffers
- Fix stamp properties; add --nofilter
- Only publish the most recent certificates
- Include the signature in SignedCert
- cache: do not forget to include the server PK in the hash computation
- Implement a simple cache for shared keys
- Add support for stamps (dnscrypt-proxy 2.x), and update the documentation
- In key rotation, old certs should be provided too, see #109.
- fixes #111, cert/key expires in 24 hours by default for safety see discussion: https://github.com/jedisct1/dnscrypt-proxy/issues/520
- docs: suggest user to generate short-term key pairs and use key-rotation mechanism See #111.

## v0.3.0

- XChaCha20 supported
- a lot of tests added
- and many bug fixes and improvements

## v0.2.2

- remove GPLv2, release under the ISC license
- update example secret key / cert, etc
- fix compiler/linker flags handling

## v0.2.1

- Rename --provider-publickey-fingerprint to --show-provider-publickey-fingerprint. It's more conventional to use a verb if you want to do some action, like gen-provider-keypair.
- Use TCP_QUICKACK instead of TCP_NODELAY if available (Linux 2.4.4+) See https://news.ycombinator.com/item?id=10608356
- Send a short packet with TC set if the query_len < response_len
- Support sending server cert over tcp
- Use the certificate timestamp as a serial number instead of a fixed serial.
- And some other minor fixes.

## v0.2.0

- Import argparse sources files directly.
