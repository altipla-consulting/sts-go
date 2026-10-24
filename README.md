# sts-go

Authenticate Connect RPC requests with the STS service at https://sts.altipla.consulting.

## Install

```sh
go get github.com/altipla-consulting/sts-go
```

## Usage

The module exports package `sts`. Register the interceptor on your unary handlers:

```go
import (
	"os"

	"connectrpc.com/connect"
	"github.com/altipla-consulting/errors"
	"github.com/altipla-consulting/sts-go"
)

interceptor := sts.NewInterceptor(os.Getenv("STS_VERIFIER_TOKEN"), "documents.read")
handlerOptions := connect.WithInterceptors(interceptor)
```

Pass `handlerOptions` to your generated Connect handler constructor. Clients must send
`Authorization: Bearer <key>`. STS verifies the key using your verifier token, and the
interceptor requires every supplied permission before calling the handler. Omit the
permissions to accept any key that STS successfully verifies.

Local environments are detected automatically using
[`env.IsLocal()`](https://github.com/altipla-consulting/env). Locally, the interceptor
accepts only `Authorization: Bearer local-token` and skips remote verification and
permission checks. The verifier token is unused in local environments.

The interceptor applies to unary RPCs; streaming RPCs are not authenticated by it.

### Permissions inside handlers

Register the interceptor without permissions to authenticate every method, then use
`sts.RequirePermissions` inside methods that need specific permissions:

```go
interceptor := sts.NewInterceptor(os.Getenv("STS_VERIFIER_TOKEN"))
handlerOptions := connect.WithInterceptors(interceptor)
```

For example, in a generated Connect handler implementation:

```go
func (s *DocumentsService) Delete(ctx context.Context, req *connect.Request[pb.DeleteRequest]) (*connect.Response[pb.DeleteResponse], error) {
	if err := sts.RequirePermissions(ctx, "documents.delete"); err != nil {
		return nil, errors.Trace(err)
	}

	// Delete the document.
	return connect.NewResponse(&pb.DeleteResponse{}), nil
}
```

Use your generated service and protobuf types in place of the example types above.
Pass the handler's context to the helper; the interceptor stores verified permissions
there. Every supplied permission is required. Missing permissions return
`connect.CodePermissionDenied`; calling the helper without the authentication
interceptor returns `missing authentication interceptor`, even when no permissions
are supplied.

You can also keep service-wide permissions in `NewInterceptor` and require additional
permissions inside individual handlers. Both checks return `connect.CodePermissionDenied`
for missing permissions. Locally, a request authenticated with `local-token` skips
both checks.

## Contributing

You can make pull requests or create issues in GitHub. Any code you send should be
formatted using `make gofmt`.

## License

MIT License
