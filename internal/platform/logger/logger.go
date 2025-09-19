package logger

import (
	"log/slog"
	"os"
)

// New creates and returns a new slog.Logger instance.
// The handler is set to JSON for machine-readable logs.
func New(serviceName string) *slog.Logger {
	log := slog.New(
		slog.NewJSONHandler(os.Stdout, nil),
	).With(
		slog.String("service", serviceName),
	)

	return log
}
