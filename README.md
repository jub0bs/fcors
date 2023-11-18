# jub0bs/fcors

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://pkg.go.dev/github.com/jub0bs/fcors)
[![license](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://github.com/jub0bs/fcors/raw/main/LICENSE)
[![build](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml/badge.svg)](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml)
[![codecov](https://codecov.io/gh/jub0bs/fcors/branch/main/graph/badge.svg?token=N208BHWQTM)](https://codecov.io/gh/jub0bs/fcors)
[![goreport](https://goreportcard.com/badge/jub0bs/fcors)](https://goreportcard.com/report/jub0bs/fcors)

A principled CORS middleware library for Go.

- [About CORS](https://github.com/jub0bs/fcors/#about-cors)
- [Design philosophy](https://github.com/jub0bs/fcors/#design-philosophy)
- [Praise for fcors](https://github.com/jub0bs/fcors/#praise-for-fcors)
- [Installation](https://github.com/jub0bs/fcors/#installation)
- [Example](https://github.com/jub0bs/fcors/#example)
- [Documentation](https://github.com/jub0bs/fcors/#documentation)
- [Code coverage](https://github.com/jub0bs/fcors/#code-coverage)
- [Benchmarks](https://github.com/jub0bs/fcors/#benchmarks)
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

The following program builds a CORS middleware
that allows anonymous requests from Web origin `https://example.com`,
with any HTTP method among `GET`, `POST`, `PUT`, or `DELETE`,
and possibly with request header `Authorization`.
The CORS middleware in question is then applied
to a simple handler bound to the `/hello` endpoint.

```go
package main

import (
  "fmt"
  "io"
  "net/http"
  "os"

  "github.com/jub0bs/fcors"
)

func main() {
  cors, err := fcors.AllowAccess(
    fcors.FromOrigins("https://example.com"),
    fcors.WithMethods(
      http.MethodGet,
      http.MethodPost,
      http.MethodPut,
      http.MethodDelete,
    ),
    fcors.WithRequestHeaders("Authorization"),
  )
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }
  http.Handle("/hello", cors(http.HandlerFunc(helloHandler)))
  if err := http.ListenAndServe(":8080", nil); err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }
}

func helloHandler(w http.ResponseWriter, _ *http.Request) {
  io.WriteString(w, "Hello, world!\n")
}
``` 

Try it out yourself by saving this program to a file named `server.go`.
You may need to adjust the port number if port 8080 happens to be unavailable
on your machine. Then build and run your server:

```shell
go build server.go
./server
```

If no error occurred, the server is now running on `localhost:8080`
and the `/hello` resource is now configured for CORS as desired.

## Documentation

The documentation is available on [pkg.go.dev][pkgsite].

Moreover, guidance on how to use jub0bs/fcors with third-party Web frameworks
and HTTP toolkits can be found in [jub0bs/fcors-examples][fcors-examples].

## Code coverage

![coverage](https://codecov.io/gh/jub0bs/fcors/branch/main/graphs/sunburst.svg?token=N208BHWQTM)

## Benchmarks

Some benchmarks pitting jub0bs/fcors against [rs/cors][rs-cors]
are available in [jub0bs/fcors-benchmarks][fcors-benchmarks].

## License

All source code is covered by the [MIT License][license].

[fcors-benchmarks]: https://github.com/jub0bs/fcors-benchmarks
[fcors-examples]: https://github.com/jub0bs/fcors-examples
[fearless-cors]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[funcopts]: https://www.youtube.com/watch?v=5uM6z7RnReE
[license]: https://github.com/jub0bs/fcors/blob/main/LICENSE
[mdn-cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[mdn-sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[net-http]: https://pkg.go.dev/net/http
[pkgsite]: https://pkg.go.dev/github.com/jub0bs/fcors
[rs-cors]: https://github.com/rs/cors
[stripe]: https://stripe.com
