package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// These cases all reject before the user lookup, so no database is required.
// The happy path (valid token -> FindUserByEmail) is exercised by the Emberfall
// E2E suite, which has a database.
func TestMiddleware_Rejections(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(next)

	tidMismatch := newClaims(entraIssuer)
	tidMismatch.Tid = "not-the-pinned-tenant"

	cases := []struct {
		name   string
		setTok func(r *http.Request)
	}{
		{
			name:   "missing header",
			setTok: func(r *http.Request) {},
		},
		{
			name: "unknown issuer",
			setTok: func(r *http.Request) {
				r.Header.Set(headerField, mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey1, newClaims("https://attacker.example.com/v2.0")))
			},
		},
		{
			name: "entra tid mismatch",
			setTok: func(r *http.Request) {
				r.Header.Set(headerField, mustSign(t, jwt.SigningMethodRS256, sharedKid, rsaKey1, tidMismatch))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled = false
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
			tc.setTok(req)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if nextCalled {
				t.Error("next handler should not be called on rejected request")
			}
		})
	}
}
