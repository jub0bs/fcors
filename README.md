# jub0bs/fcors

[![Go Reference](https://pkg.go.dev/badge/github.com/jub0bs/fcors.svg)](https://pkg.go.dev/github.com/jub0bs/fcors)
[![license](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://github.com/jub0bs/fcors/raw/main/LICENSE)
[![build](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml/badge.svg)](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml)
[![codecov](https://codecov.io/gh/jub0bs/fcors/branch/main/graph/badge.svg?token=N208BHWQTM)](https://codecov.io/gh/jub0bs/fcors)
[![goreport](https://goreportcard.com/badge/jub0bs/fcors)](https://goreportcard.com/report/jub0bs/fcors)

An experimental CORS middleware library for Go.

Unless you're a big fan of [functional options][funcopts],
you should use [github.com/jub0bs/cors][jub0bs-cors] instead.

- [About CORS](https://github.com/jub0bs/fcors/#about-cors)
- [Design philosophy](https://github.com/jub0bs/fcors/#design-philosophy)
- [Praise for fcors](https://github.com/jub0bs/fcors/#praise-for-jub0bsfcors)
- [Installation](https://github.com/jub0bs/fcors/#installation)
- [Example](https://github.com/jub0bs/fcors/#example)
- [Documentation](https://github.com/jub0bs/fcors/#documentation)
- [Code coverage](https://github.com/jub0bs/fcors/#code-coverage)
- [License](https://github.com/jub0bs/fcors/#license)

## About CORS

The [Same-Origin Policy (SOP)][mdn-sop] is a security mechanism that
Web browsers implement to protect their users.
In particular, the SOP restricts cross-origin network access
in terms of both sending and reading.
[Cross-Origin Resource Sharing (CORS)][mdn-cors] is a protocol that
lets servers instruct browsers to relax those restrictions for select clients.

jub0bs/fcors allows you to configure and build [net/http][net-http] middleware
that implement CORS.

## Design philosophy

jub0bs/fcors is designed to be both easier to use and harder to misuse
than other CORS middleware libraries; see
[_Fearless CORS: a design philosophy for CORS middleware libraries
(and a Go implementation)_][fearless-cors] and
[_Useful Functional-Options Tricks for Better Libraries_
(GopherCon Europe 2023)][funcopts].

## Praise for jub0bs/fcors

> I really like the declarative API. It lets you say what behavior you want
> rather than setting specific headers. It means that, as a user,
> you don’t have to relearn the nuances of CORS every time you want to make
> a change.

Paul Carleton (Staff Software Engineer at [Stripe][stripe])

## Installation

```shell
go get github.com/jub0bs/fcors
```

jub0bs/fcors requires Go 1.21 or above.

## Example

The following program demonstrates how to create a CORS middleware that

- allows anonymous access from Web origin `https://example.com`,
- with requests whose method is either `GET` or `POST`,
- and (optionally) with request header `Authorization`,

and how to apply the middleware in question to all the resources accessible
under some `/api/` path:

```go
package main

import (
  "io"
  "log"
  "net/http"

  "github.com/jub0bs/fcors"
)

func main() {
  mux := http.NewServeMux()
  mux.HandleFunc("GET /hello", handleHello) // note: not configured for CORS

  // create CORS middleware
  cors, err := fcors.AllowAccess(
    fcors.FromOrigins("https://example.com"),
    fcors.WithMethods(http.MethodGet, http.MethodPost),
    fcors.WithRequestHeaders("Authorization"),
  )
  if err != nil {
    log.Fatal(err)
  }

  api := http.NewServeMux()
  api.HandleFunc("GET /users", handleUsersGet)
  api.HandleFunc("POST /users", handleUsersPost)
  mux.Handle("/api/", http.StripPrefix("/api", cors(api))) // note: method-less pattern here

  log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleHello(w http.ResponseWriter, _ *http.Request) {
  io.WriteString(w, "Hello, World!")
}

func handleUsersGet(w http.ResponseWriter, _ *http.Request) {
  // omitted
}

func handleUsersPost(w http.ResponseWriter, _ *http.Request) {
  // omitted
}
``` 

Try it out yourself by saving this program to a file named `server.go`.
You may need to adjust the port number if port 8080 happens to be unavailable
on your machine. Then build and run your server:

```shell
go build server.go
./server
```

If no error occurred, the server is now running on `localhost:8080` and the
various resources accessible under the `/api/` path are now configured for
CORS as desired.

## Documentation

The documentation is available on [pkg.go.dev][pkgsite].

## Code coverage

![coverage](https://codecov.io/gh/jub0bs/fcors/branch/main/graphs/sunburst.svg?token=N208BHWQTM)

## License

All source code is covered by the [MIT License][license].

[fearless-cors]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[funcopts]: https://www.youtube.com/watch?v=5uM6z7RnReE
[jub0bs-cors]: https://github.com/jub0bs/cors
[license]: https://github.com/jub0bs/fcors/blob/main/LICENSE
[mdn-cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[mdn-sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[net-http]: https://pkg.go.dev/net/http
[pkgsite]: https://pkg.go.dev/github.com/jub0bs/fcors
[stripe]: https://stripe.com
