// Package sts authenticates Connect RPC requests using the STS service.
package sts

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"buf.build/gen/go/altipla/sts/connectrpc/go/v2/verify/verifyconnect"
	pbsts "buf.build/gen/go/altipla/sts/protocolbuffers/go/verify"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/altipla-consulting/env"
	"github.com/altipla-consulting/errors"
	"google.golang.org/protobuf/proto"
)

type authenticationKey struct{}

type authentication struct {
	permissions []string
	local       bool
}

// NewInterceptor authenticates handler requests and requires every listed permission.
// Verified permissions are available to RequirePermissions in the handler context.
// When env.IsLocal reports a local environment, only local-token is accepted and remote verification and permission checks are skipped.
func NewInterceptor(verifierToken string, permissions ...string) connect.ServerInterceptor {
	transport := connecthttp.NewTransport(http.DefaultClient, "https://sts.altipla.consulting")
	client := verifyconnect.NewVerifyServiceClient(connect.NewClient(transport))
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

			req := pbsts.VerifyRequest_builder{
				Key: proto.String(parts[1]),
			}.Build()
			verifyCtx, info := connect.NewClientContext(ctx)
			info.RequestHeader().Set("Authorization", "Bearer "+verifierToken)
			resp, err := client.Verify(verifyCtx, req)
			if err != nil {
				if connectErr := new(connect.Error); errors.As(err, &connectErr) && connectErr.Code() == connect.CodeNotFound && connectErr.Message() == "key not found" {
					return connect.NewError(connect.CodeUnauthenticated, "wrong key")
				}
				return errors.Trace(err)
			}

			ctx = context.WithValue(ctx, authenticationKey{}, authentication{permissions: resp.GetPermissions()})
			if err := RequirePermissions(ctx, permissions...); err != nil {
				return errors.Trace(err)
			}

			return next(ctx, spec, stream)
		}
	}
}

// RequirePermissions requires an authenticated context from NewInterceptor and every listed permission.
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
