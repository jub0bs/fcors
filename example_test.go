package fcors_test

import (
	"io"
	"log"
	"net/http"

	"github.com/jub0bs/fcors"
)

func ExampleAllowAccess() {
	cors, err := fcors.AllowAccess(
		fcors.FromAnyOrigin(),
		fcors.WithMethods(
			http.MethodGet,
			http.MethodDelete,
			http.MethodPost,
			http.MethodPut,
		),
		fcors.WithRequestHeaders(
			"Authorization",
			"Content-Type",
		),
		fcors.MaxAgeInSeconds(30),
	)
	if err != nil {
		log.Fatal(err)
	}
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	})

	http.Handle("/hello", cors(helloHandler))
}

func ExampleAllowAccessWithCredentials() {
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins(
			"https://example.com",
		),
		fcors.WithMethods(
			http.MethodGet,
			http.MethodDelete,
			http.MethodPost,
			http.MethodPut,
		),
		fcors.WithRequestHeaders(
			"Content-Type",
		),
		fcors.MaxAgeInSeconds(30),
	)
	if err != nil {
		log.Fatal(err)
	}
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	})

	http.Handle("/hello", cors(helloHandler))
}
