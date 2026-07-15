package api

import "fmt"

// APIError is a non-2xx response from dnsd.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("dnsd: %s (%s, http %d)", e.Message, e.Code, e.Status)
	}
	return fmt.Sprintf("dnsd: %s (http %d)", e.Message, e.Status)
}
