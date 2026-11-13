package sts

import "context"

// Actor identifies the verified JWT caller by issuer and subject.
type Actor struct {
	Issuer  string
	Subject string
}

// ActorFromContext returns the verified JWT actor. It panics if the context has no actor.
func ActorFromContext(ctx context.Context) Actor {
	auth, ok := ctx.Value(authenticationKey{}).(authentication)
	if !ok || auth.actor == nil {
		panic("missing authenticated actor")
	}
	return *auth.actor
}
