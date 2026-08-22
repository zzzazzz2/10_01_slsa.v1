package main

import (
	"crypto"
	"flag"
	"fmt"
	jwtMiddleware "github.com/codeby-student/go-service/pkg/middleware/jwt"
	"github.com/codeby-student/go-service/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/exp/slices"
	"log"
	"net/http"
	"os"
)

var (
	mode       = flag.String("mode", "production", "Operate mode (production or test)")
	validModes = []string{"production", "test"}
)

func main() {
	if !slices.Contains(validModes, *mode) {
		log.Fatal("invalid operate mode")
	}

	publicKey, err := os.ReadFile(fmt.Sprintf("%s/public.key", *mode))
	if err != nil {
		log.Fatal(fmt.Errorf("error read public key: %w", err))
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	jwt := jwtMiddleware.Jwt(crypto.SHA512, publicKey)
	r.Use(jwt)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		payload, ok := jwtMiddleware.FromContext(r.Context())
		if !ok {
			utils.WriteResponse(w, http.StatusUnauthorized, "err.auth_required")
			return
		}

		utils.WriteResponse(w, http.StatusOK, fmt.Sprintf("Welcome, %s!", payload.Subject))
	})
	err = http.ListenAndServe(":8888", r)
	if err != nil {
		log.Fatal(err)
	}
}
