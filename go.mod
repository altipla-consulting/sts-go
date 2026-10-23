module github.com/altipla-consulting/sts-go

go 1.26.0

require (
	buf.build/gen/go/altipla/sts/connectrpc/go v1.21.0-20260730112142-3c00f9556107.1
	buf.build/gen/go/altipla/sts/protocolbuffers/go v1.36.12-20260730112142-3c00f9556107.2
	connectrpc.com/connect v1.21.1
	github.com/altipla-consulting/errors v1.5.1
	google.golang.org/protobuf v1.36.12
)

require github.com/altipla-consulting/env v0.3.0
