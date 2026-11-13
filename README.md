# sts-go

Authenticate Connect RPC requests with Google ID tokens, Convex JWTs, or existing
STS keys verified by https://sts.altipla.consulting. Create HTTP clients that send
Google ID tokens automatically.

## Install

```sh
go get github.com/altipla-consulting/sts-go
```

## Usage

The module exports package `sts`. Configure authentication at application startup,
then register an interceptor on your server:

```go
import (
	"os"

	"connectrpc.com/connect/v2"
	"github.com/altipla-consulting/sts-go"
)

sts.Configure(sts.Config{
	VerifierToken: os.Getenv("STS_VERIFIER_TOKEN"),
	Audience:      "https://documents.example.com",
	Actors: []sts.ActorRule{
		sts.GoogleSubject("123456789012345678901", "documents.read", "documents.delete"),
		sts.ConvexApp("gentle-fox-123", "documents.read"),
	},
})

server := connect.NewServer(sts.Require("documents.read"))
```

Register your generated Connect handlers on `server`. Clients must send
`Authorization: Bearer <token>`. The interceptor authenticates unary and streaming
RPCs and requires every permission passed to `sts.Require` before calling the handler.
Use `sts.Authenticate()` to authenticate requests without requiring specific permissions.

`sts.Configure` must run before creating `sts.Require` or `sts.Authenticate`
interceptors. Interceptors share public key caches and retain the configuration
they were created with; public keys are fetched on demand. Configuring actor rules
without an audience panics, as does passing an empty permission to `sts.Require`.

### Accepted credentials

- `sts.GoogleSubject(subject, permissions...)` accepts a Google service account or
  user by its stable `sub` claim, not its email address. Google tokens must use the
  issuer `https://accounts.google.com` and an RS256 signature.
- `sts.ConvexApp(deployment, permissions...)` accepts every subject signed by the
  named deployment. Pass the deployment name, such as `gentle-fox-123`, rather than
  its URL. Tokens must use the issuer `https://<deployment>.convex.cloud` and an
  ES256 signature.
- `VerifierToken` enables verification of existing opaque STS keys. Their
  permissions come from the STS service. Leave it empty to disable legacy keys;
  omit `Audience` and `Actors` if you only accept STS keys.

JWT signatures, expiration, issuer, and audience are verified before actor rules
grant permissions. Set `Audience` to the receiving service's identifier and use
the same value when obtaining tokens. Permissions from all matching actor rules
are additive. A valid JWT whose subject matches no rule returns
`connect.CodePermissionDenied`; invalid JWTs or untrusted issuers return
`connect.CodeUnauthenticated`.

### Google clients

Use `sts.NewGoogleClient` to obtain an HTTP client that sends Google ID tokens using
application default credentials and refreshes them as needed. The credentials must
support ID token generation, and their Google subject must be allowed by the server.
For a Connect v2 client:

```go
import (
	"context"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/altipla-consulting/errors"
	"github.com/altipla-consulting/sts-go"
)

func newClient(ctx context.Context) (*connect.Client, error) {
	httpClient, err := sts.NewGoogleClient(ctx, "https://documents.example.com")
	if err != nil {
		return nil, errors.Trace(err)
	}

	transport := connecthttp.NewTransport(httpClient, "https://documents.example.com")
	return connect.NewClient(transport), nil
}
```

Pass the resulting Connect client to your generated service client constructor.
The token audience identifies the receiving service independently of the request
path; it must match the server's configured `Audience`.

### Permissions inside handlers

Register `sts.Authenticate()` after configuration to authenticate every method, then use
`sts.RequirePermissions` inside methods that need specific permissions:

```go
server := connect.NewServer(sts.Authenticate())
```

For example, in a generated Connect handler implementation:

```go
func (s *DocumentsService) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	if err := sts.RequirePermissions(ctx, "documents.delete"); err != nil {
		return nil, errors.Trace(err)
	}

	// Delete the document.
	return &pb.DeleteResponse{}, nil
}
```

Use your generated service and protobuf types in place of the example types above.
The handler example uses `context` and `github.com/altipla-consulting/errors`.
Pass the handler's context to the helper; the interceptor stores verified permissions
there. Every supplied permission is required. Missing permissions return
`connect.CodePermissionDenied`; calling the helper without the authentication
interceptor returns `missing authentication interceptor`, even when no permissions
are supplied.

You can also keep service-wide permissions in `sts.Require` and require additional
permissions inside individual handlers. Both checks return `connect.CodePermissionDenied`
for missing permissions. Locally, a request authenticated with `local-token` skips
both checks.

### Verified actors

For requests authenticated with a JWT, retrieve the verified issuer and subject
inside a handler with:

```go
actor := sts.ActorFromContext(ctx)
```

`actor.Issuer` and `actor.Subject` identify the caller. `sts.ActorFromContext` panics
when no verified JWT actor exists, including requests authenticated with an STS key
or `local-token`. Use it only in handlers that expect JWT authentication.

### Local development

Local environments are detected automatically using
[`env.IsLocal()`](https://github.com/altipla-consulting/env). Locally, interceptors
accept only `Authorization: Bearer local-token` and skip remote verification and
permission checks. `sts.NewGoogleClient` sends this token automatically without
loading Google credentials. Configuration is still required before creating
`sts.Require` or `sts.Authenticate` interceptors, and actor rules still require an
audience.

### Migrating from NewInterceptor

`sts.NewInterceptor(verifierToken, permissions...)` remains available for STS keys
but is deprecated. Configure legacy key verification at startup:

```go
sts.Configure(sts.Config{VerifierToken: verifierToken})
```

Then use `sts.Require("documents.read")` to require permissions or
`sts.Authenticate()` when only authentication is needed.
Add `Audience` and `Actors` to accept JWTs alongside existing keys.

## Contributing

You can make pull requests or create issues in GitHub. Any code you send should be
formatted using `make gofmt`.

## License

MIT License
