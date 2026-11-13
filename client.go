package sts

import (
	"context"
	"net/http"

	"github.com/altipla-consulting/env"
	"github.com/altipla-consulting/errors"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// NewGoogleClient returns an HTTP client that sends Google ID tokens using the
// application's default credentials and refreshes them as needed. Set audience
// to the receiving service's identifier, independently of the request path.
// When env.IsLocal reports a local environment, it sends local-token instead.
func NewGoogleClient(ctx context.Context, audience string) (*http.Client, error) {
	if env.IsLocal() {
		source := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "local-token"})
		return oauth2.NewClient(ctx, source), nil
	}

	client, err := idtoken.NewClient(ctx, audience)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return client, nil
}
