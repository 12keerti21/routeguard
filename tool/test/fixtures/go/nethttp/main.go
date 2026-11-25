// A deliberately vulnerable API on the standard library only, for routeguard's tests and runtime checks.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
)

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
	IsAdmin      bool   `json:"isAdmin"`
}

type Order struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Item   string `json:"item"`
}

type Note struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Text   string `json:"text"`
}

type store struct {
	mu     sync.Mutex
	users  map[string]*User
	orders map[string]*Order
	notes  map[string]*Note
}

func (s *store) FindOrder(id string) (*Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	return o, ok
}

func (s *store) FindNote(id string) (*Note, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notes[id]
	return n, ok
}

var db = &store{
	users: map[string]*User{
		"1": {ID: "1", Email: "alice@test.local", PasswordHash: "$2b$10$alicehash"},
		"2": {ID: "2", Email: "bob@test.local", PasswordHash: "$2b$10$bobhash"},
	},
	orders: map[string]*Order{"10": {ID: "10", UserID: "1", Item: "alice's order"}, "20": {ID: "20", UserID: "2", Item: "bob's order"}},
	notes:  map[string]*Note{"100": {ID: "100", UserID: "1", Text: "alice's note"}},
}

const jwtSecret = "hardcoded-secret"

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// a token whose signature is never checked: alg none and doctored claims pass
func userIDFromToken(r *http.Request) string {
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	json.Unmarshal(raw, &claims)
	return claims.Sub
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userIDFromToken(r) == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	for _, u := range db.users {
		if u.Email == body.Email && body.Password == "pass-"+u.ID {
			token := b64(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + b64(map[string]string{"sub": u.ID}) + ".c2ln"
			writeJSON(w, map[string]string{"token": token})
			return
		}
	}
	http.Error(w, `{"error":"wrong email or password"}`, http.StatusUnauthorized)
}

// API1: any signed-in user reads any order
func getOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	order, ok := db.FindOrder(id)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, order)
}

// safe: the note must belong to the caller
func getNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := userIDFromToken(r)
	note, ok := db.FindNote(id)
	if !ok || note.UserID != userID {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, note)
}

func listOrders(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromToken(r)
	out := []*Order{}
	for _, o := range db.orders {
		if o.UserID == userID {
			out = append(out, o)
		}
	}
	writeJSON(w, out)
}

// API3: the whole user, hash included
func me(w http.ResponseWriter, r *http.Request) {
	var user *User = db.users[userIDFromToken(r)]
	writeJSON(w, user)
}

// API7: fetches whatever URL the client sends
func fetchAvatar(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	writeJSON(w, map[string]int{"status": resp.StatusCode})
}

// API8: a malformed id brings back a stack trace
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.ContainsAny(id, "'\"<") {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "panic: bad id\n"+string(debug.Stack()))
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

// API9: a development route left in
func debugVars(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]int{"users": len(db.users)})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", login)
	mux.HandleFunc("GET /api/orders", requireAuth(listOrders))
	mux.HandleFunc("GET /api/orders/{id}", requireAuth(getOrder))
	mux.HandleFunc("GET /api/notes/{id}", requireAuth(getNote))
	mux.HandleFunc("GET /api/me", requireAuth(me))
	mux.HandleFunc("GET /api/users/{id}", requireAuth(getUser))
	mux.HandleFunc("GET /api/avatar", requireAuth(fetchAvatar))
	mux.HandleFunc("GET /dev/vars", debugVars)
	http.ListenAndServe(":8080", cors(mux))
}
