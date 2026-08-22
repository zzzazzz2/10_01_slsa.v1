package jwt

import (
	"context"
	"crypto"
	auth "github.com/codeby-student/go-service/pkg/auth/jwt"
	"github.com/codeby-student/go-service/pkg/utils"
	"net/http"
	"strings"
	"time"
)

type contextKey string

var payloadContextKey = contextKey("jwt")

func Jwt(hash crypto.Hash, key []byte) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			authorization := request.Header.Get("Authorization")
			if authorization == "" {
				next.ServeHTTP(writer, request)
				return
			}

			if !strings.HasPrefix(authorization, "Bearer ") {
				next.ServeHTTP(writer, request)
				return
			}

			token := authorization[len("Bearer "):]

			ok, err := auth.Verify(token, hash, key)
			if err != nil {
				utils.WriteResponse(writer, http.StatusBadRequest, "err.auth_error")
				return
			}

			if !ok {
				utils.WriteResponse(writer, http.StatusUnauthorized, "err.unauthorized")
				return
			}

			payload, err := auth.Decode(token)
			if err != nil {
				utils.WriteResponse(writer, http.StatusBadRequest, "err.auth_error")
				return
			}

			if auth.Expired(payload.Expire, time.Now()) {
				utils.WriteResponse(writer, http.StatusBadRequest, "err.auth_error")
				return
			}

			ctx := context.WithValue(request.Context(), payloadContextKey, payload)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func FromContext(ctx context.Context) (*auth.Payload, bool) {
	payload, ok := ctx.Value(payloadContextKey).(*auth.Payload)
	return payload, ok
}

func IsContextEmpty(ctx context.Context) bool {
	return nil == ctx.Value(payloadContextKey)
}

func IsContextNonEmpty(ctx context.Context) bool {
	return !IsContextEmpty(ctx)
}
