package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CMS-Enterprise/ztmf/backend/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// Test fixtures shared across token_test.go and middleware_test.go, set up in
// TestMain before the config singleton is initialized.
const (
	entraIssuer  = "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0"
	entra2Issuer = "https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/v2.0"
	oktaIssuer   = "https://example.okta.com"
	entraTenant  = "22222222-2222-2222-2222-222222222222"
	sharedKid    = "shared-kid-1" // deliberately identical across entra/entra2 to exercise cache namespacing
	oktaKid      = "okta-key-1"
	hs256Secret  = "test-hs256-secret"
	headerField  = "x-test-token"
)

var (
	rsaKey1 *rsa.PrivateKey   // entra
	rsaKey2 *rsa.PrivateKey   // entra2 (same kid as entra, different key)
	ecKey   *ecdsa.PrivateKey // okta (legacy PEM/ES256)
)

func TestMain(m *testing.M) {
	rsaKey1 = mustRSA()
	rsaKey2 = mustRSA()
	ecKey = mustEC()

	entraSrv := httptest.NewServer(jwksHandler(rsaKey1, sharedKid))
	defer entraSrv.Close()
	entra2Srv := httptest.NewServer(jwksHandler(rsaKey2, sharedKid))
	defer entra2Srv.Close()
	oktaSrv := httptest.NewServer(pemHandler(ecKey, oktaKid))
	defer oktaSrv.Close()

	providers := []map[string]any{
		{"name": "entra", "issuer": entraIssuer, "token_key_url": entraSrv.URL, "tenant_id": entraTenant, "jwks": true},
		{"name": "entra2", "issuer": entra2Issuer, "token_key_url": entra2Srv.URL, "jwks": true},
		{"name": "okta", "issuer": oktaIssuer, "token_key_url": oktaSrv.URL + "/", "jwks": false},
	}
	providersJSON, _ := json.Marshal(providers)

	os.Setenv("AUTH_HS256_SECRET", hs256Secret)
	os.Setenv("AUTH_HEADER_FIELD", headerField)
	os.Setenv("AUTH_PROVIDERS", string(providersJSON))

	os.Exit(m.Run())
}

func TestDecodeJWT_EntraRS256(t *testing.T) {
	claims := newClaims(entraIssuer)
	claims.PreferredUsername = "doctor@hhs.gov"
	claims.Tid = entraTenant
	tokenStr := mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey1, claims)

	tkn, err := decodeJWT(tokenStr)
	if err != nil {
		t.Fatalf("decodeJWT returned error: %v", err)
	}
	if !tkn.Valid {
		t.Fatal("expected valid Entra RS256 token")
	}
	got := tkn.Claims.(*Claims)
	if got.PreferredUsername != "doctor@hhs.gov" {
		t.Errorf("preferred_username = %q, want doctor@hhs.gov", got.PreferredUsername)
	}
}

func TestDecodeJWT_LegacyES256(t *testing.T) {
	claims := newClaims(oktaIssuer)
	claims.Email = "ren@example.okta.com"
	tokenStr := mustSign(t, jwt.SigningMethodES256, oktaKid, ecKey, claims)

	tkn, err := decodeJWT(tokenStr)
	if err != nil {
		t.Fatalf("decodeJWT returned error: %v", err)
	}
	if !tkn.Valid {
		t.Fatal("expected valid Okta ES256 token")
	}
}

func TestDecodeJWT_HS256Local(t *testing.T) {
	claims := newClaims("") // local HS256 tokens carry no issuer
	claims.Email = "grand.moff@deathstar.empire"
	tokenStr := mustSign(t, jwt.SigningMethodHS256, "", []byte(hs256Secret), claims)

	tkn, err := decodeJWT(tokenStr)
	if err != nil {
		t.Fatalf("decodeJWT returned error: %v", err)
	}
	if !tkn.Valid {
		t.Fatal("expected valid HS256 local token")
	}
}

func TestDecodeJWT_UnknownIssuer(t *testing.T) {
	claims := newClaims("https://attacker.example.com/v2.0")
	// validly signed by a real key, but the issuer is not configured
	tokenStr := mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey1, claims)

	if _, err := decodeJWT(tokenStr); err == nil {
		t.Fatal("expected error for token with unknown issuer")
	}
}

// TestDecodeJWT_CacheNamespacing proves the key cache is keyed by issuer:kid:
// two providers share an identical kid but use different signing keys, and both
// tokens must validate. A kid-only cache would return the first provider's key
// for the second token and fail verification.
func TestDecodeJWT_CacheNamespacing(t *testing.T) {
	tok1 := mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey1, newClaims(entraIssuer))
	tok2 := mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey2, newClaims(entra2Issuer))

	for name, tokenStr := range map[string]string{"entra": tok1, "entra2": tok2} {
		tkn, err := decodeJWT(tokenStr)
		if err != nil {
			t.Fatalf("%s: decodeJWT returned error: %v", name, err)
		}
		if !tkn.Valid {
			t.Fatalf("%s: expected valid token despite shared kid", name)
		}
	}
}

func TestUserIdentifier(t *testing.T) {
	cases := []struct {
		name              string
		preferredUsername string
		email             string
		want              string
	}{
		{"prefers UPN", "upn@hhs.gov", "mail@hhs.gov", "upn@hhs.gov"},
		{"falls back to email", "", "mail@cms.hhs.gov", "mail@cms.hhs.gov"},
		{"both empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := userIdentifier(&Claims{PreferredUsername: tc.preferredUsername, Email: tc.email})
			if got != tc.want {
				t.Errorf("userIdentifier = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckProviderClaims(t *testing.T) {
	cfg := config.GetInstance()
	entra := cfg.ProviderForIssuer(entraIssuer)
	okta := cfg.ProviderForIssuer(oktaIssuer)

	if err := checkProviderClaims(entra, &Claims{Tid: entraTenant}); err != nil {
		t.Errorf("matching tid should pass: %v", err)
	}
	if err := checkProviderClaims(entra, &Claims{Tid: "wrong-tenant"}); err == nil {
		t.Error("mismatched tid should fail")
	}
	if err := checkProviderClaims(entra, &Claims{}); err == nil {
		t.Error("missing tid on a tenant-pinned provider should fail")
	}
	if err := checkProviderClaims(okta, &Claims{}); err != nil {
		t.Errorf("provider without tenant pin should pass: %v", err)
	}
	if err := checkProviderClaims(nil, &Claims{}); err != nil {
		t.Errorf("nil provider should pass: %v", err)
	}
}

// --- helpers ---

func newClaims(issuer string) Claims {
	now := time.Now()
	return Claims{
		Name: "Test User",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
}

func mustSign(t *testing.T, method jwt.SigningMethod, kid string, key any, claims Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func mustEC() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// jwksHandler serves a JWKS document containing the public half of key under kid.
func jwksHandler(key *rsa.PrivateKey, kid string) http.Handler {
	pub := key.PublicKey
	doc := map[string]any{
		"keys": []map[string]any{{
			"kid": kid,
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	body, _ := json.Marshal(doc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
}

// pemHandler serves the PKIX PEM-encoded public key at /<kid>, mirroring the
// AWS ALB OIDC key endpoint.
func pemHandler(key *ecdsa.PrivateKey, kid string) http.Handler {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+kid {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})
}
