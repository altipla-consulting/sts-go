package sts

import (
	"context"

	"connectrpc.com/connect/v2"
	oauth2 "github.com/altipla-consulting/connect-oauth2"
	"github.com/altipla-consulting/env"
)

// GoogleIDToken sends Google ID tokens using the
// application's default credentials and refreshes them as needed. Set audience
// to the receiving service's identifier, independently of the request path.
// Outside production, it sends local-token instead.
func GoogleIDToken(audience string) connect.ClientInterceptor {
	if env.IsProduction() {
		return oauth2.GoogleIDToken(true, audience)
	}

	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			info, ok := connect.CallInfoForClientContext(ctx)
			if !ok {
				return nil, connect.NewError(connect.CodeInternal, "missing client call info")
			}
			info.RequestHeader().Set("Authorization", "Bearer local-token")
			return next(ctx, spec)
		}
	}
}
