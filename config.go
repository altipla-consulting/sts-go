package sts

import (
	"context"
	"net/http"
	"strings"

	"buf.build/gen/go/altipla/sts/connectrpc/go/v2/verify/verifyconnect"
	pbsts "buf.build/gen/go/altipla/sts/protocolbuffers/go/verify"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/altipla-consulting/env"
	"github.com/altipla-consulting/errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/protobuf/proto"
)

const googleIssuer = "https://accounts.google.com"

// Config defines the credentials and actors accepted by the application.
// Audience must match the JWT audience and is required when Actors is nonempty.
// VerifierToken enables remote STS verification for existing opaque keys.
// Locally, only local-token is accepted and permission checks are skipped.
type Config struct {
	VerifierToken string
	Audience      string
	Actors        []ActorRule
}

var configured *authenticator

// Configure sets application-wide authentication before interceptors are created.
// Interceptors share public key caches and retain the configuration they were
// created with. Invalid configuration panics; public keys are fetched on demand.
func Configure(config Config) {
	configured = newAuthenticator(config)
}

// ActorRule grants permissions to a Google account or a Convex deployment.
// Construct rules with GoogleSubject, GoogleServiceAccount, or ConvexApp.
// Matching grants are additive.
type ActorRule struct {
	issuer      string
	subject     string
	email       string
	permissions []string
}

// GoogleSubject accepts the stable Google sub claim of a service account or user.
// Pass the account's stable subject ID.
func GoogleSubject(subject string, permissions ...string) ActorRule {
	if subject == "" {
		panic("missing google subject")
	}
	return ActorRule{
		issuer:      googleIssuer,
		subject:     subject,
		permissions: permissions,
	}
}

// GoogleServiceAccount accepts a service account by its verified email claim.
// Tokens must include email and email_verified. A recreated account with the
// same email is also accepted; use GoogleSubject to bind to a specific account ID.
func GoogleServiceAccount(email string, permissions ...string) ActorRule {
	if !strings.HasSuffix(email, ".gserviceaccount.com") {
		panic("invalid google service account email")
	}
	return ActorRule{
		issuer:      googleIssuer,
		email:       email,
		permissions: permissions,
	}
}

// ConvexApp accepts every subject signed by the named deployment.
// Pass its deployment name, such as gentle-fox-123.
func ConvexApp(deployment string, permissions ...string) ActorRule {
	if deployment == "" {
		panic("missing convex deployment")
	}
	return ActorRule{
		issuer:      "https://" + deployment + ".convex.cloud",
		permissions: permissions,
	}
}

type authenticator struct {
	verifierToken string
	client        verifyconnect.VerifyServiceClient
	verifiers     map[string]*oidc.IDTokenVerifier
	actors        []ActorRule
}

func newAuthenticator(config Config) *authenticator {
	if len(config.Actors) > 0 && config.Audience == "" {
		panic("missing jwt audience")
	}
	auth := &authenticator{
		verifierToken: config.VerifierToken,
		verifiers:     make(map[string]*oidc.IDTokenVerifier),
		actors:        config.Actors,
	}
	if config.VerifierToken != "" {
		transport := connecthttp.NewTransport(http.DefaultClient, "https://sts.altipla.consulting")
		auth.client = verifyconnect.NewVerifyServiceClient(connect.NewClient(transport))
	}
	for _, actor := range auth.actors {
		if auth.verifiers[actor.issuer] != nil {
			continue
		}
		var provider oidc.ProviderConfig
		if actor.issuer == googleIssuer {
			provider = oidc.ProviderConfig{
				IssuerURL:  googleIssuer,
				JWKSURL:    "https://www.googleapis.com/oauth2/v3/certs",
				Algorithms: []string{"RS256"},
			}
		} else {
			provider = oidc.ProviderConfig{
				IssuerURL:  actor.issuer,
				JWKSURL:    actor.issuer + "/.well-known/jwks.json",
				Algorithms: []string{"ES256"},
			}
		}
		auth.verifiers[actor.issuer] = provider.NewProvider(context.Background()).Verifier(&oidc.Config{ClientID: config.Audience})
	}
	return auth
}

func configuredAuthenticator() *authenticator {
	if configured == nil {
		panic("missing sts configuration")
	}
	return configured
}

func (auth *authenticator) interceptor(permissions []string) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			info, _ := connect.CallInfoForServerContext(ctx)
			authorization := info.RequestHeader().Get("Authorization")
			if authorization == "" {
				return connect.NewError(connect.CodeUnauthenticated, "missing authorization header")
			}
			parts := strings.Split(authorization, " ")
			if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
				return connect.NewError(connect.CodeUnauthenticated, "invalid authorization header")
			}
			if env.IsLocal() {
				if parts[1] != "local-token" {
					return connect.NewError(connect.CodeUnauthenticated, "invalid local token, it should be local-token")
				}
				ctx = context.WithValue(ctx, authenticationKey{}, authentication{local: true})
				return next(ctx, spec, stream)
			}

			verified, err := auth.verify(ctx, parts[1])
			if err != nil {
				return errors.Trace(err)
			}

			ctx = context.WithValue(ctx, authenticationKey{}, verified)
			if err := RequirePermissions(ctx, permissions...); err != nil {
				return errors.Trace(err)
			}

			return next(ctx, spec, stream)
		}
	}
}

func (auth *authenticator) verify(ctx context.Context, token string) (authentication, error) {
	if strings.Count(token, ".") == 2 {
		return auth.verifyJWT(ctx, token)
	}
	return auth.verifyKey(ctx, token)
}

func (auth *authenticator) verifyJWT(ctx context.Context, raw string) (authentication, error) {
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "invalid jwt")
	}
	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "invalid jwt")
	}
	// The unverified issuer selects a configured verifier.
	verifier := auth.verifiers[claims.Issuer]
	if verifier == nil {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "untrusted jwt issuer")
	}
	verified, err := verifier.Verify(ctx, raw)
	if err != nil {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "invalid jwt")
	}
	if verified.Subject == "" {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "missing jwt subject")
	}

	var googleClaims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if verified.Issuer == googleIssuer {
		if err := verified.Claims(&googleClaims); err != nil {
			return authentication{}, connect.NewError(connect.CodeUnauthenticated, "invalid google claims")
		}
	}

	result := authentication{actor: &Actor{Issuer: verified.Issuer, Subject: verified.Subject}}
	matched := false
	for _, rule := range auth.actors {
		if rule.issuer != verified.Issuer {
			continue
		}
		if rule.subject != "" && rule.subject != verified.Subject {
			continue
		}
		if rule.email != "" && (!googleClaims.EmailVerified || rule.email != googleClaims.Email) {
			continue
		}
		matched = true
		result.permissions = append(result.permissions, rule.permissions...)
	}
	if !matched {
		return authentication{}, connect.NewError(connect.CodePermissionDenied, "actor not allowed")
	}
	return result, nil
}

func (auth *authenticator) verifyKey(ctx context.Context, key string) (authentication, error) {
	if auth.client == nil {
		return authentication{}, connect.NewError(connect.CodeUnauthenticated, "legacy keys disabled")
	}
	req := pbsts.VerifyRequest_builder{Key: proto.String(key)}.Build()
	verifyCtx, info := connect.NewClientContext(ctx)
	info.RequestHeader().Set("Authorization", "Bearer "+auth.verifierToken)
	resp, err := auth.client.Verify(verifyCtx, req)
	if err != nil {
		if connectErr := new(connect.Error); errors.As(err, &connectErr) && connectErr.Code() == connect.CodeNotFound && connectErr.Message() == "key not found" {
			return authentication{}, connect.NewError(connect.CodeUnauthenticated, "wrong key")
		}
		return authentication{}, errors.Trace(err)
	}
	return authentication{permissions: resp.GetPermissions()}, nil
}
