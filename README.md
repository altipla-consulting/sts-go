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

## Contributing

You can make pull requests or create issues in GitHub. Any code you send should be
formatted using `make gofmt`.

## License

MIT License
