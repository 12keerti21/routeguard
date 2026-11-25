package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Use(Authenticator)
		r.Get("/docs/{docID}", getDoc)
		r.With(AdminOnly).Delete("/docs/{docID}", deleteDoc)
	})
	r.Mount("/internal", internalRouter())
	http.ListenAndServe(":8080", r)
}

func internalRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/health", health)
	return r
}

func Authenticator(next http.Handler) http.Handler { return next }
func AdminOnly(next http.Handler) http.Handler     { return next }
func health(w http.ResponseWriter, r *http.Request) {}

// vulnerable: unscoped read
func getDoc(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "docID")
	rows, _ := sqlDB.Query("SELECT * FROM docs WHERE id = $1", id)
	_ = rows
}

func deleteDoc(w http.ResponseWriter, r *http.Request) {}
