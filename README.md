# fcors

[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://pkg.go.dev/github.com/jub0bs/fcors)
[![license](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://github.com/jub0bs/fcors/raw/main/LICENSE)
[![build](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml/badge.svg)](https://github.com/jub0bs/fcors/actions/workflows/fcors.yml)
[![codecov](https://codecov.io/gh/jub0bs/fcors/branch/main/graph/badge.svg?token=N208BHWQTM)](https://codecov.io/gh/jub0bs/fcors)
[![goreport](https://goreportcard.com/badge/jub0bs/fcors)](https://goreportcard.com/report/jub0bs/fcors)

A principled CORS middleware library for Go.

- [About CORS](https://github.com/jub0bs/fcors/#about-cors)
- [Design philosophy](https://github.com/jub0bs/fcors/#design-philosophy)
- [Installation](https://github.com/jub0bs/fcors/#installation)
- [Example](https://github.com/jub0bs/fcors/#example)
- [Documentation](https://github.com/jub0bs/fcors/#documentation)
- [Code coverage](https://github.com/jub0bs/fcors/#code-coverage)
- [License](https://github.com/jub0bs/fcors/#license)

## About CORS

[Cross-Origin Resource Sharing (CORS)][mdn-cors] is a mechanism
that lets servers instruct browsers to relax, for select clients,
some restrictions (in terms of both sending and reading)
enforced by the [Same-Origin Policy (SOP)][mdn-sop]
on cross-origin network access.

fcors allows you to configure and build [net/http][net-http] middleware
that implement CORS.

## Design philosophy

fcors is designed to be both easier to use and harder to misuse
than other CORS middleware libraries; see
[_Fearless CORS: a design philosophy for CORS middleware libraries
(and a Go implementation)_][fearless-cors].

## Installation

```shell
go get github.com/jub0bs/fcors
```

fcors requires Go 1.20 or above.

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

Moreover, guidance on how to use fcors with third-party Web frameworks
and HTTP toolkits can be found in [jub0bs/fcors-examples][fcors-examples].

## Code coverage

![coverage](https://codecov.io/gh/jub0bs/fcors/branch/main/graphs/sunburst.svg?token=N208BHWQTM)

## License

All source code is covered by the [MIT License][license].

[fcors-examples]: https://github.com/jub0bs/fcors-examples
[fearless-cors]: https://jub0bs.com/posts/2023-02-08-fearless-cors/
[license]: https://github.com/jub0bs/fcors/blob/main/LICENSE
[mdn-cors]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
[mdn-sop]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
[net-http]: https://pkg.go.dev/net/http
[pkgsite]: https://pkg.go.dev/github.com/jub0bs/fcors
