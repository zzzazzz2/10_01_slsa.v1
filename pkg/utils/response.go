package utils

import (
	"log"
	"net/http"
)

func WriteResponse(w http.ResponseWriter, status int, body string) {
	w.WriteHeader(status)
	_, err := w.Write([]byte(body))
	if err != nil {
		log.Print(err)
	}
	return
}
