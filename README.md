# tower-csrf

[![CI](https://github.com/yawn/tower-csrf/actions/workflows/rust.yml/badge.svg)](https://github.com/yawn/tower-csrf/actions/workflows/rust.yml)

This is _experimental_ middleware for tower. It has not received a formal audit.

It provides modern CSRF protection as outlined in a [blogpost](https://words.filippo.io/csrf/) by Filippo Valsorda, discussing the research background for integrating CSRF protection in Go 1.25's [`net/http`](https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/net/http/csrf.go).

This repository has been discussed in [tower](https://github.com/tower-rs/tower-http/discussions/600) and the [axum](https://github.com/tokio-rs/axum/discussions/3436) project respectively.

This boils down to (quoting from the blog):

1. Allow all GET, HEAD, or OPTIONS requests - this implied that no relevant state changes are performed at endpoints behind such safe methods
2. If the Origin header matches an allow-list of trusted origins, allow the request
3. If the Sec-Fetch-Site header is present and the value is `same-origin` or `none`, allow the request, otherwise reject
4. If neither the Sec-Fetch-Site nor the Origin headers are present, allow the request
5. If the Origin header’s host (including the port) matches the Host header, allow the request, otherwise reject it

See [tests/csrf.rs](tests/axum.rs) for an example using Axum.
