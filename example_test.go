package fcors_test

import (
	"io"
	"log"
	"net/http"

	"github.com/jub0bs/fcors"
)

func ExampleAllowAccess() {
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
