package middleware

import (
	"context"
	"net"
	"net/http"
)

// RequestMetadataKey is the context key for request metadata.
const RequestMetadataKey contextKey = "request_metadata"

// RequestMetadata contains metadata extracted from the HTTP request.
// NOTE: This type has been defined to make future additions to metadata,
// e.g. Geo-location, device type etc. trivial to implement.
type RequestMetadata struct {
	ClientIP string
	// possibly add geo-location etc. later
}

// ExtractRequestMetadata middleware extracts request metadata and stores it in context.
// (It should be placed after chi.RealIP middleware in the chain).
func ExtractRequestMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := &RequestMetadata{
			ClientIP: extractIP(r),
		}

		ctx := context.WithValue(r.Context(), RequestMetadataKey, metadata)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestMetadata retrieves request metadata from context.
// Returns a safe default if metadata is not found.
func GetRequestMetadata(ctx context.Context) *RequestMetadata {
	if metadata, ok := ctx.Value(RequestMetadataKey).(*RequestMetadata); ok {
		return metadata
	}

	return &RequestMetadata{
		ClientIP: "unknown",
	}
}

// extractIP extracts the client IP from the request.
// It relies on chi.RealIP middleware already having processed the request.
// TODO: The reliance on chi middleware specifically might be a bit fragile,
// look into making it router agnostic if possible.
func extractIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
