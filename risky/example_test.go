package risky_test

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jub0bs/fcors"
	"github.com/jub0bs/fcors/risky"
)

func ExampleDangerouslyTolerateSubdomainsOfPublicSuffixes() {
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins("https://*.com"),
		risky.DangerouslyTolerateSubdomainsOfPublicSuffixes(),
	)
	if err != nil {
		// This branch would get executed if the call to
		// risky.DangerouslyTolerateSubdomainsOfPublicSuffixes were missing
		// above.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	})

	http.Handle("/hello_public_suffix", cors(helloHandler))
}

func ExampleDangerouslyTolerateInsecureOrigins() {
	cors, err := fcors.AllowAccessWithCredentials(
		fcors.FromOrigins("http://example.com"),
		risky.DangerouslyTolerateInsecureOrigins(),
	)
	if err != nil {
		// This branch would get executed if the call to
		// risky.DangerouslyTolerateInsecureOrigins were missing above.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	helloHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	})
	http.Handle("/hello_insecure_origin", cors(helloHandler))
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
