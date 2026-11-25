package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	api.Use(requireLogin)
	api.HandleFunc("/items/{id}", getItem).Methods(http.MethodGet, "OPTIONS")
	api.HandleFunc("/items/{id:[0-9]+}/owner", getItemOwner).Methods("GET")
	http.ListenAndServe(":8080", r)
}

func requireLogin(next http.Handler) http.Handler { return next }

// safe: the item must belong to the caller
func getItem(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	user := currentUser(r)
	item, _ := findItem(id)
	if item.OwnerID != user.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func getItemOwner(w http.ResponseWriter, r *http.Request) {}

type Item struct{ OwnerID string }
type Account struct{ ID string }

func currentUser(r *http.Request) Account { return Account{} }
func findItem(id string) (Item, error)    { return Item{}, nil }
