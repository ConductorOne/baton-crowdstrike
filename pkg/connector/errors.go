package connector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"google.golang.org/grpc/codes"
)

// wrapCrowdStrikeError wraps errors from the CrowdStrike gofalcon SDK with appropriate gRPC codes.
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
	// This is necessary because gofalcon SDK doesn't always expose structured errors
	errMsg := strings.ToLower(err.Error())

	// Authentication errors
	if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "unauthorized") {
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
	if strings.Contains(errMsg, "500") || strings.Contains(errMsg, "503") ||
		strings.Contains(errMsg, "internal server error") || strings.Contains(errMsg, "service unavailable") {
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

// extractCrowdStrikeError attempts to extract error code and message from CrowdStrike SDK errors.
func extractCrowdStrikeError(err error) (int, string) {
	if err == nil {
		return 0, ""
	}

	// Check if error contains MsaAPIError fields (common in CrowdStrike API responses)
	type csError interface {
		GetErrors() []models.MsaAPIError
	}

	var csErr csError
	if errors.As(err, &csErr) {
		errs := csErr.GetErrors()
		if len(errs) > 0 {
			firstErr := errs[0]
			if firstErr.Code != nil && firstErr.Message != nil {
				code := int(*firstErr.Code)
				message := *firstErr.Message
				return code, message
			}
		}
	}

	// If we can't extract structured error, return 0 to indicate no specific error found
	return 0, ""
}

// isConflictError checks if the error is a 409 Conflict error from CrowdStrike API.
func isConflictError(err error) bool {
	if err == nil {
		return false
	}

	code, _ := extractCrowdStrikeError(err)
	if code == 409 {
		return true
	}

	// Fallback: check error message for 409 or conflict indicators
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "409") || strings.Contains(errMsg, "conflict")
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
