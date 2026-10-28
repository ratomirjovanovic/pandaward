//go:build ignore

// Fixture for go.yaml; excluded from the Pandaward build.
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func lookup(db *sql.DB, id string) {
	// ruleid: pandaward-go-sql-string
	db.Query(fmt.Sprintf("SELECT * FROM invoices WHERE id = %s", id))
	// ruleid: pandaward-go-sql-string
	db.Exec("DELETE FROM invoices WHERE id = " + id)
	// ok: pandaward-go-sql-string
	db.Query("SELECT * FROM invoices WHERE id = $1", id)
}

func run(dir string) {
	// ruleid: pandaward-go-shell-exec
	exec.Command("sh", "-c", "ls "+dir).Run()
	// ok: pandaward-go-shell-exec
	exec.Command("sh", "-c", "ls -la").Run()
	// ok: pandaward-go-shell-exec
	exec.Command("ls", dir).Run()
}

func client() *http.Client {
	// ruleid: pandaward-go-tls-insecure
	cfg := &tls.Config{InsecureSkipVerify: true}
	// ok: pandaward-go-tls-insecure
	safe := &tls.Config{MinVersion: tls.VersionTLS12}
	_ = safe
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func newSessionToken() int64 {
	// ruleid: pandaward-go-weak-random
	return rand.Int63()
}

func shuffleSeed() int {
	// ok: pandaward-go-weak-random
	return rand.Intn(10)
}

func proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: pandaward-go-ssrf
	resp, _ := http.Get(target)
	// ok: pandaward-go-ssrf
	status, _ := http.Get("https://api.example.org/status")
	_, _ = resp, status
}

func files(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: pandaward-go-path-traversal
	b, _ := os.ReadFile(filepath.Join("/srv/files", name))
	// ok: pandaward-go-path-traversal
	c, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))
	w.Write(append(b, c...))
}
