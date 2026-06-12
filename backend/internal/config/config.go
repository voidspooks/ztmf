package config

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/CMS-Enterprise/ztmf/backend/internal/secrets"
	"github.com/caarlos0/env/v10"
)

var cfg *config

// AuthProvider describes one OIDC issuer the API will accept tokens from.
// Multiple providers support the HHS dual-IdP requirement (CMS Okta + HHS
// Entra). Values are supplied at deploy time via the AUTH_PROVIDERS env var
// (JSON array) or Secrets Manager; tenant-specific Entra values are tracked in
// the internal epic (CMS-Enterprise/ztmf-misc#170).
type AuthProvider struct {
	Name        string `json:"name"`
	Issuer      string `json:"issuer"`        // expected `iss` claim, matched verbatim (Entra includes the /v2.0 suffix)
	TokenKeyUrl string `json:"token_key_url"` // JWKS URI when JWKS is true, else legacy per-kid PEM base URL
	TenantID    string `json:"tenant_id"`     // optional: if set, the token `tid` claim must equal this (Entra tenant pinning)
	JWKS        bool   `json:"jwks"`          // true: token_key_url is a JWKS JSON endpoint (RS256); false: legacy per-kid PEM (ES256)
}

type smtp struct {
	User string `json:"user" env:"SMTP_USER"`
	Pass string `json:"pass" env:"SMTP_PASS"`
	Host string `json:"host" env:"SMTP_HOST"`
	Port int16  `json:"port" env:"SMTP_PORT"`
	From string `json:"from" env:"SMTP_FROM"`
	// certs is a chain comprised of root and intermediate certificates pulled from secrets manager
	Certs                    *x509.CertPool
	ConfigSecretID           *string `env:"SMTP_CONFIG_SECRET_ID"`
	CertRootSecretID         *string `env:"SMTP_CA_ROOT_SECRET_ID"`
	CertIntermediateSecretID *string `env:"SMTP_CA_INT_SECRET_ID"`
}

// config is shared by all binaries with values derived from environment variables
type config struct {
	Env      string `env:"ENVIRONMENT" envDefault:"production"`
	Port     string `env:"PORT" envDefault:"3000"`
	CertFile string `env:"CERT_FILE"`
	KeyFile  string `env:"KEY_FILE"`
	Region   string `env:"AWS_REGION" envDefault:"us-east-1"`
	Auth     struct {
		HS256_SECRET string `env:"AUTH_HS256_SECRET"`
		TokenKeyUrl  string `env:"AUTH_TOKEN_KEY_URL"` // legacy single-IdP key endpoint (ALB ES256 PEM); synthesizes a provider when AUTH_PROVIDERS is unset
		HeaderField  string `env:"AUTH_HEADER_FIELD"`  // the header that includes encoded JWT from OIDC IDP
		// ProvidersJSON is a JSON array of AuthProvider configs supplied at
		// deploy time (env var or Secrets Manager). Parsed into Providers.
		ProvidersJSON string         `env:"AUTH_PROVIDERS"`
		Providers     []AuthProvider `env:"-"`
	}
	Db struct {
		Host        string  `env:"DB_ENDPOINT"`
		Port        string  `env:"DB_PORT" envDefault:"5432"`
		Name        string  `env:"DB_NAME"`
		User        string  `env:"DB_USER"`
		Pass        string  `env:"DB_PASS"`
		SecretId    string  `env:"DB_SECRET_ID"`
		PopulateSql *string `env:"DB_POPULATE"` // path to sql to populate test database
	}
	// SMTP config will be loaded from env vars if provided.
	// If config secret is provided, struct field values will be overwritten by unmarshalling JSON from config secret value hence the pointer to struct
	SMTP *smtp
}

// GetInstance returns a singleton of *config
func GetInstance() *config {
	if cfg == nil {
		var (
			err  error
			once sync.Once
		)

		once.Do(func() {
			var (
				smtpCfgSecret, SmtpCertRootSecret, SmtpCertIntermediateSecret *secrets.Secret
				secretVal                                                     *string
			)

			log.Println("initializing config...")

			cfg = &config{
				SMTP: &smtp{},
			}
			err = env.Parse(cfg)
			if err != nil {
				log.Println("error parsing environment variables: ", err)
				return
			}

			if err = cfg.initAuthProviders(); err != nil {
				log.Println("error initializing auth providers: ", err)
				return
			}

			if cfg.SMTP.ConfigSecretID != nil {
				smtpCfgSecret, err = secrets.NewSecret(*cfg.SMTP.ConfigSecretID)
				if err != nil {
					return
				}

				err = smtpCfgSecret.Unmarshal(cfg.SMTP)
				if err != nil {
					return
				}
			}

			if cfg.SMTP.CertRootSecretID != nil && cfg.SMTP.CertIntermediateSecretID != nil {
				cfg.SMTP.Certs = x509.NewCertPool()

				SmtpCertRootSecret, err = secrets.NewSecret(*cfg.SMTP.CertRootSecretID)
				if err != nil {
					return
				}

				secretVal, err = SmtpCertRootSecret.Value(context.Background())
				if err != nil {
					return
				}

				if !cfg.SMTP.Certs.AppendCertsFromPEM([]byte(*secretVal)) {
					err = errors.New("failed to append root cert")
					return
				}

				SmtpCertIntermediateSecret, err = secrets.NewSecret(*cfg.SMTP.CertIntermediateSecretID)
				if err != nil {
					return
				}

				secretVal, err = SmtpCertIntermediateSecret.Value(context.Background())
				if err != nil {
					return
				}

				if !cfg.SMTP.Certs.AppendCertsFromPEM([]byte(*secretVal)) {
					err = errors.New("failed to append intermediate cert")
					return
				}
			}
		})

		if err != nil {
			// anything depending on the config instance can't possibly work if initialization failed, so exit
			log.Fatal("failed to initialize config: ", err)
			return nil
		}
	}

	return cfg
}

// IsLocal reports whether the API is running in the local development
// environment (ENVIRONMENT=local). Used to gate dev-only behavior such as
// just-in-time user creation, which must not happen in any other environment.
func (c *config) IsLocal() bool {
	return c.Env == "local"
}

// IsLocalOrTest reports whether the API is running in an ephemeral local or
// E2E test environment (ENVIRONMENT=local or test). Used to gate test-data
// seeding, which is safe in both but must never run against a deployed
// environment. Kept distinct from IsLocal because seeding applies to the E2E
// test stack while just-in-time user creation deliberately does not.
func (c *config) IsLocalOrTest() bool {
	return c.Env == "local" || c.Env == "test"
}

// initAuthProviders populates Auth.Providers from the AUTH_PROVIDERS JSON env
// var. For backward compatibility, if no providers are configured but the
// legacy AUTH_TOKEN_KEY_URL is set, it synthesizes a single catch-all provider
// so existing single-IdP deployments keep working with no config change.
func (c *config) initAuthProviders() error {
	if c.Auth.ProvidersJSON != "" {
		if err := json.Unmarshal([]byte(c.Auth.ProvidersJSON), &c.Auth.Providers); err != nil {
			return fmt.Errorf("parsing AUTH_PROVIDERS: %w", err)
		}
	}

	if len(c.Auth.Providers) == 0 && c.Auth.TokenKeyUrl != "" {
		c.Auth.Providers = []AuthProvider{{
			Name:        "legacy",
			TokenKeyUrl: c.Auth.TokenKeyUrl,
		}}
	}

	return nil
}

// ProviderForIssuer returns the configured provider whose Issuer matches iss.
// A provider with an empty Issuer acts as a catch-all (legacy single-IdP mode)
// and is only returned when no issuer-specific provider matches. Returns nil
// when the issuer is unknown, which callers treat as an authentication failure.
func (c *config) ProviderForIssuer(iss string) *AuthProvider {
	var catchAll *AuthProvider
	for i := range c.Auth.Providers {
		p := &c.Auth.Providers[i]
		if p.Issuer == "" {
			catchAll = p
			continue
		}
		if p.Issuer == iss {
			return p
		}
	}
	return catchAll
}
