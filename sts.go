// Package sts authenticates Connect RPC requests using the STS service.
package sts

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"buf.build/gen/go/altipla/sts/connectrpc/go/verify/verifyconnect"
	pbsts "buf.build/gen/go/altipla/sts/protocolbuffers/go/verify"
	"connectrpc.com/connect"
	"github.com/altipla-consulting/env"
	"github.com/altipla-consulting/errors"
	"google.golang.org/protobuf/proto"
)

// NewInterceptor authenticates unary handler requests and requires every listed permission.
// When env.IsLocal reports a local environment, only local-token is accepted and remote verification and permission checks are skipped.
func NewInterceptor(verifierToken string, permissions ...string) connect.Interceptor {
	client := verifyconnect.NewVerifyServiceClient(http.DefaultClient, "https://sts.altipla.consulting")
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, in connect.AnyRequest) (connect.AnyResponse, error) {
			authorization := in.Header().Get("Authorization")
			if authorization == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
			}
			parts := strings.Split(authorization, " ")
			if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization header"))
			}
			if env.IsLocal() {
				if parts[1] != "local-token" {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid local token, it should be local-token"))
				}
				return next(ctx, in)
			}

			connectReq := connect.NewRequest(pbsts.VerifyRequest_builder{
				Key: proto.String(parts[1]),
			}.Build())
			connectReq.Header().Set("Authorization", "Bearer "+verifierToken)
			resp, err := client.Verify(ctx, connectReq)
			if err != nil {
				if connectErr := new(connect.Error); errors.As(err, &connectErr) && connectErr.Code() == connect.CodeNotFound && connectErr.Message() == "key not found" {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("wrong key"))
				}
				return nil, errors.Trace(err)
			}

			for _, permission := range permissions {
				if !slices.Contains(resp.Msg.GetPermissions(), permission) {
					slog.Warn("missing permission", slog.String("perm", permission))
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.Errorf("missing permission %q", permission))
				}
			}

			return next(ctx, in)
		}
	})
}
