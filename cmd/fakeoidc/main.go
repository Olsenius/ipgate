// Command fakeoidc runs the test suite's fake OIDC provider for local manual
// testing of ipgate. It auto-approves every login as the configured user.
// Development only: it is not built into the Docker image.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/Olsenius/ipgate/internal/oidctest"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address")
	issuer := flag.String("issuer", "http://127.0.0.1:9999", "issuer URL (must match how clients reach this server)")
	clientID := flag.String("client-id", "ipgate", "OIDC client id")
	clientSecret := flag.String("client-secret", "dev-secret", "OIDC client secret")
	sub := flag.String("sub", "dev-user", "sub claim")
	name := flag.String("name", "Dev User", "name claim")
	groups := flag.String("groups", "media,admins", "comma-separated groups claim")
	flag.Parse()

	p := oidctest.NewProvider(strings.TrimRight(*issuer, "/"), *clientID, *clientSecret)
	p.Set(func(s *oidctest.Settings) {
		s.User = oidctest.User{Sub: *sub, Name: *name, PreferredUsername: *sub, Email: *sub + "@example.com", Groups: strings.Split(*groups, ",")}
	})
	log.Printf("fake OIDC provider %s listening on %s (client %q)", *issuer, *addr, *clientID)
	log.Fatal(http.ListenAndServe(*addr, p.Handler()))
}
