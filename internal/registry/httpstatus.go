package registry

import (
	"errors"
	"net/http"

	"hextrap.io/artifacts/internal/rbac"
)

// HTTPStatus maps registry errors to HTTP status codes for every protocol
// handler.
func HTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrExists), errors.Is(err, ErrVersionExists), errors.Is(err, ErrFileExists),
		errors.Is(err, ErrRepoNotEmpty), errors.Is(err, rbac.ErrLastAdmin):
		return http.StatusConflict
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrConfirmationMismatch), errors.Is(err, ErrBlobUnknown):
		return http.StatusBadRequest
	case errors.Is(err, ErrQuotaExceeded):
		return http.StatusInsufficientStorage
	case errors.Is(err, ErrReadOnly):
		return http.StatusMethodNotAllowed
	case errors.Is(err, ErrDigestMismatch), errors.Is(err, ErrUpstreamUnavailable):
		return http.StatusBadGateway
	case errors.Is(err, ErrBlocked):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

// PublicMessage is safe to show clients: registry errors are descriptive,
// anything else is internal and gets a generic message.
func PublicMessage(err error) string {
	if HTTPStatus(err) == http.StatusInternalServerError {
		return "internal error"
	}
	return err.Error()
}
