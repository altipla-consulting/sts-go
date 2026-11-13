// Package sts authenticates clients and Connect RPC handlers.
package sts

import (
	"context"
	"log/slog"
	"slices"

	"connectrpc.com/connect/v2"
	"github.com/altipla-consulting/errors"
)

type authenticationKey struct{}

type authentication struct {
	permissions []string
	local       bool
	actor       *Actor
}

// RequirePermissions requires an authenticated context and every listed permission.
// Permission checks are skipped for requests authenticated with local-token in local environments.
func RequirePermissions(ctx context.Context, permissions ...string) error {
	auth, ok := ctx.Value(authenticationKey{}).(authentication)
	if !ok {
		return errors.Errorf("missing authentication interceptor")
	}
	if auth.local {
		return nil
	}

	for _, permission := range permissions {
		if !slices.Contains(auth.permissions, permission) {
			slog.Warn("missing permission", slog.String("perm", permission))
			return connect.Errorf(connect.CodePermissionDenied, "missing permission %q", permission)
		}
	}
	return nil
}

// NewInterceptor authenticates existing STS keys without app-wide configuration.
// Deprecated: use Configure followed by Require or Authenticate instead.
func NewInterceptor(verifierToken string, permissions ...string) connect.ServerInterceptor {
	auth := newAuthenticator(Config{VerifierToken: verifierToken})
	return auth.interceptor(permissions)
}

// Require authenticates requests and requires every listed permission.
// Call Configure before creating interceptors. Empty permissions panic.
func Require(permission string, permissions ...string) connect.ServerInterceptor {
	permissions = append([]string{permission}, permissions...)
	for _, permission := range permissions {
		if permission == "" {
			panic("missing required permission")
		}
	}
	return configuredAuthenticator().interceptor(permissions)
}

// Authenticate authenticates requests without requiring specific permissions.
// Call Configure first, and use RequirePermissions in handlers as needed.
func Authenticate() connect.ServerInterceptor {
	return configuredAuthenticator().interceptor(nil)
}
