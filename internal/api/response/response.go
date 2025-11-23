// Package response provides helpers for writing JSON responses.
package response

import (
	"encoding/json"
	"net/http"
)

// JSON writes a JSON response with the given status code and data.
func JSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")

	if data != nil {
		body, err := json.Marshal(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, writeErr := w.Write([]byte(`{"code":"INTERNAL_ERROR","message":"Failed to encode response"}`))
			if writeErr != nil {
				return writeErr
			}
			return err
		}
		w.WriteHeader(status)
		_, err = w.Write(body)
		return err
	}

	w.WriteHeader(status)
	return nil
}

// Error writes a JSON error response with code and message.
func Error(w http.ResponseWriter, status int, code, message string) error {
	return JSON(w, status, map[string]string{
		"code":    code,
		"message": message,
	})
}
