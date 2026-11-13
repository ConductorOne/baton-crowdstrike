package connector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	openAPIRuntime "github.com/go-openapi/runtime"
	"google.golang.org/grpc/codes"
)

// httpCoder is satisfied by all typed gofalcon SDK error responses
// (e.g. QueryUserV1InternalServerError, QueryUserV1Forbidden, etc.)
// which expose the HTTP status code via Code().
type httpCoder interface {
	error
	Code() int
}

// wrapCrowdStrikeError maps CrowdStrike gofalcon errors into Baton-friendly
// gRPC codes, falling back to message inspection when the SDK hides status data.
func wrapCrowdStrikeError(err error, operation string) error {
	if err == nil {
		return nil
	}

	// Try to extract CrowdStrike-specific error information from structured response
	code, message := extractCrowdStrikeError(err)
	if code != 0 {
		grpcCode := httpStatusToGRPCCode(code)
		return uhttp.WrapErrors(
			grpcCode,
			fmt.Sprintf("%s: %s", operation, message),
			err,
		)
	}

	// Fallback: Inspect error message for common HTTP status code patterns
	// This is necessary because some errors (e.g. OAuth2 token failures,
	// identity protection GraphQL errors) bypass the gofalcon SDK client.
	errMsg := strings.ToLower(err.Error())

	// Authentication errors
	if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "unauthorized") ||
		strings.Contains(errMsg, "access_denied") || strings.Contains(errMsg, "invalid client") {
		return uhttp.WrapErrors(codes.Unauthenticated, fmt.Sprintf("%s: authentication failed", operation), err)
	}

	// Permission errors
	if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "forbidden") {
		return uhttp.WrapErrors(codes.PermissionDenied, fmt.Sprintf("%s: permission denied", operation), err)
	}

	// Not Found errors
	if strings.Contains(errMsg, "404") || strings.Contains(errMsg, "not found") {
		return uhttp.WrapErrors(codes.NotFound, fmt.Sprintf("%s: resource not found", operation), err)
	}

	// Rate limiting errors
	if strings.Contains(errMsg, "429") || strings.Contains(errMsg, "too many requests") || strings.Contains(errMsg, "rate limit") {
		return uhttp.WrapErrors(codes.ResourceExhausted, fmt.Sprintf("%s: rate limit exceeded", operation), err)
	}

	// Server errors (5xx)
	if strings.Contains(errMsg, "500") || strings.Contains(errMsg, "502") ||
		strings.Contains(errMsg, "503") || strings.Contains(errMsg, "504") ||
		strings.Contains(errMsg, "internal server error") || strings.Contains(errMsg, "service unavailable") ||
		strings.Contains(errMsg, "bad gateway") || strings.Contains(errMsg, "gateway timeout") {
		return uhttp.WrapErrors(codes.Unavailable, fmt.Sprintf("%s: service unavailable", operation), err)
	}

	// Timeout errors
	if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "deadline exceeded") {
		return uhttp.WrapErrors(codes.DeadlineExceeded, fmt.Sprintf("%s: request timeout", operation), err)
	}

	// Network/connection errors
	if strings.Contains(errMsg, "connection") || strings.Contains(errMsg, "network") {
		return uhttp.WrapErrors(codes.Unavailable, fmt.Sprintf("%s: network error", operation), err)
	}

	// Default: treat as unknown to avoid unintended retries
	// Unknown is safer than Unavailable because Unavailable triggers automatic retries
	return uhttp.WrapErrors(codes.Unknown, fmt.Sprintf("%s: unknown error", operation), err)
}

// extractCrowdStrikeError extracts the HTTP status code from gofalcon SDK
// error responses. The SDK uses two error patterns:
//
//  1. Typed response errors (e.g. QueryUserV1InternalServerError) for known
//     status codes — these implement the httpCoder interface via Code() int.
//
//  2. Generic runtime.APIError for status codes not covered by the swagger
//     spec — these carry the code in the APIError.Code field.
func extractCrowdStrikeError(err error) (int, string) {
	if err == nil {
		return 0, ""
	}

	// Typed gofalcon SDK errors expose HTTP status via Code().
	var coder httpCoder
	if errors.As(err, &coder) {
		code := coder.Code()
		if code >= 400 {
			return code, coder.Error()
		}
	}

	// Generic go-openapi runtime.APIError for unhandled status codes
	// (e.g. 401 or 502 when the swagger spec only lists 200/400/403/429/500).
	var apiErr *openAPIRuntime.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Code >= 400 {
			return apiErr.Code, apiErr.Error()
		}
	}

	return 0, ""
}

// isConflictError reports whether CrowdStrike returned a 409 Conflict, including
// untyped 409 errors from gofalcon's generic response path.
func isConflictError(err error) bool {
	if err == nil {
		return false
	}

	code, _ := extractCrowdStrikeError(err)
	if code == 409 {
		return true
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "409") || strings.Contains(errMsg, "conflict")
}

// isNotFoundError reports whether CrowdStrike returned 404 Not Found so delete
// operations can treat already-deleted users as success.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	code, _ := extractCrowdStrikeError(err)
	if code == 404 {
		return true
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "404") || strings.Contains(errMsg, "not found")
}

// httpStatusToGRPCCode maps HTTP status codes to gRPC codes.
func httpStatusToGRPCCode(statusCode int) codes.Code {
	switch statusCode {
	case 400:
		return codes.InvalidArgument
	case 401:
		return codes.Unauthenticated
	case 403:
		return codes.PermissionDenied
	case 404:
		return codes.NotFound
	case 408:
		return codes.DeadlineExceeded
	case 409:
		return codes.AlreadyExists
	case 429:
		return codes.ResourceExhausted
	case 500, 502, 503:
		return codes.Unavailable
	case 501:
		return codes.Unimplemented
	case 504:
		return codes.DeadlineExceeded
	default:
		if statusCode >= 500 {
			return codes.Unavailable
		}
		if statusCode >= 400 {
			return codes.InvalidArgument
		}
		return codes.Unknown
	}
}
