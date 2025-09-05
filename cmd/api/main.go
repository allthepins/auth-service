package main

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("Starting server on port 8080...")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Hello from auth-service")
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error serving auth-service")
	}
}
