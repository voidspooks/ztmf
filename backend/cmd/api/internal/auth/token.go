package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"

	"github.com/CMS-Enterprise/ztmf/backend/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// keys caches verification keys by "<issuer>:<kid>" so that keys from different
// providers that happen to share a kid value never collide.
var (
	keys   = make(map[string]jwt.VerificationKey)
	keysMu sync.RWMutex
)

type Claims struct {
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Tid               string `json:"tid"`
	jwt.RegisteredClaims
}

func decodeJWT(tokenString string) (*jwt.Token, error) {
	// AWS ELB does not conform to JWT standards!
	// encoded data includes illegal padding (as = chars)
	// thus making signature verification impossible with standards-conforming packages
	return jwt.ParseWithClaims(tokenString, &Claims{}, getKey,
		jwt.WithPaddingAllowed(),
		jwt.WithValidMethods([]string{"HS256", "RS256", "ES256"}),
	)
}

// userIdentifier returns the claim used to look up the application user.
// Entra populates preferred_username (UPN) and only sets email for users with a
// mailbox attribute, so preferred_username is preferred with an email fallback.
// Okta and local HS256 tokens leave preferred_username empty and fall back to
// email, preserving existing behavior.
func userIdentifier(c *Claims) string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Email
}

// checkProviderClaims enforces provider-specific claim constraints after a
// token's signature has been verified. For tenant-pinned providers (Entra) it
// rejects tokens whose `tid` claim does not match the configured tenant,
// defending against tokens issued by other Entra tenants that share the same
// issuer URL pattern.
func checkProviderClaims(provider *config.AuthProvider, c *Claims) error {
	if provider == nil {
		return nil
	}
	if provider.TenantID != "" && c.Tid != provider.TenantID {
		return fmt.Errorf("token tid %q does not match provider %q tenant", c.Tid, provider.Name)
	}
	return nil
}

// getKey resolves the verification key for a token. HS256 (local dev) is keyed
// off the shared secret; all other algorithms are routed to the provider whose
// configured issuer matches the token's unverified `iss` claim. Selecting the
// key by the unverified issuer is safe: a forged issuer simply points at a key
// the attacker cannot have signed with, so verification fails.
func getKey(token *jwt.Token) (interface{}, error) {
	cfg := config.GetInstance()

	alg, _ := token.Header["alg"].(string)
	switch alg {
	case "", "none":
		return nil, errors.New("unsupported jwt signing algorithm")
	case "HS256":
		return []byte(cfg.Auth.HS256_SECRET), nil
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}

	provider := cfg.ProviderForIssuer(claims.Issuer)
	if provider == nil {
		return nil, fmt.Errorf("unknown token issuer: %q", claims.Issuer)
	}

	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("token missing kid header")
	}

	cacheKey := provider.Issuer + ":" + kid

	keysMu.RLock()
	key, cached := keys[cacheKey]
	keysMu.RUnlock()
	if cached {
		return key, nil
	}

	key, err := fetchKey(provider, kid)
	if err != nil {
		return nil, err
	}

	keysMu.Lock()
	keys[cacheKey] = key
	keysMu.Unlock()

	return key, nil
}

// fetchKey retrieves a verification key for kid from the provider's key
// endpoint, branching on whether the endpoint serves a JWKS document (RS256) or
// a single PEM-encoded key per kid (legacy ALB, ES256).
func fetchKey(provider *config.AuthProvider, kid string) (jwt.VerificationKey, error) {
	if provider.JWKS {
		return fetchJWKSKey(provider.TokenKeyUrl, kid)
	}
	return fetchPEMKey(provider.TokenKeyUrl, kid)
}

// fetchPEMKey is the legacy path: the key endpoint returns a single PEM-encoded
// EC public key at <baseURL><kid> (AWS ALB OIDC, ES256).
func fetchPEMKey(baseURL, kid string) (jwt.VerificationKey, error) {
	res, err := http.Get(baseURL + kid)
	if err != nil {
		return nil, fmt.Errorf("fetching public key: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading public key response: %w", err)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("no PEM data found in public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ecKey, nil
}

// jwk is a single RSA key from a JWKS document.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// fetchJWKSKey fetches the provider's JWKS document and builds the RSA public
// key whose kid matches (OIDC IdPs such as Entra, RS256).
func fetchJWKSKey(jwksURL, kid string) (jwt.VerificationKey, error) {
	res, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "RSA" {
			return nil, fmt.Errorf("unsupported JWKS key type: %q", k.Kty)
		}
		return rsaPublicKeyFromJWK(k)
	}

	return nil, fmt.Errorf("no JWKS key found for kid %q", kid)
}

// rsaPublicKeyFromJWK reconstructs an RSA public key from a JWK's base64url
// modulus (n) and exponent (e).
func rsaPublicKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding JWK modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding JWK exponent: %w", err)
	}

	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("invalid JWK exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
