// Code generated by go-swagger; DO NOT EDIT.

package workflows

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// WorkflowExecutionsCombinedReader is a Reader for the WorkflowExecutionsCombined structure.
type WorkflowExecutionsCombinedReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *WorkflowExecutionsCombinedReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewWorkflowExecutionsCombinedOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewWorkflowExecutionsCombinedBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewWorkflowExecutionsCombinedForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewWorkflowExecutionsCombinedNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewWorkflowExecutionsCombinedTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewWorkflowExecutionsCombinedInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /workflows/combined/executions/v1] WorkflowExecutionsCombined", response, response.Code())
	}
}

// NewWorkflowExecutionsCombinedOK creates a WorkflowExecutionsCombinedOK with default headers values
func NewWorkflowExecutionsCombinedOK() *WorkflowExecutionsCombinedOK {
	return &WorkflowExecutionsCombinedOK{}
}

/*
WorkflowExecutionsCombinedOK describes a response with status code 200, with default header values.

OK
*/
type WorkflowExecutionsCombinedOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIExecutionResultsResponse
}

// IsSuccess returns true when this workflow executions combined o k response has a 2xx status code
func (o *WorkflowExecutionsCombinedOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this workflow executions combined o k response has a 3xx status code
func (o *WorkflowExecutionsCombinedOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined o k response has a 4xx status code
func (o *WorkflowExecutionsCombinedOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow executions combined o k response has a 5xx status code
func (o *WorkflowExecutionsCombinedOK) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow executions combined o k response a status code equal to that given
func (o *WorkflowExecutionsCombinedOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the workflow executions combined o k response
func (o *WorkflowExecutionsCombinedOK) Code() int {
	return 200
}

func (o *WorkflowExecutionsCombinedOK) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedOK  %+v", 200, o.Payload)
}

func (o *WorkflowExecutionsCombinedOK) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedOK  %+v", 200, o.Payload)
}

func (o *WorkflowExecutionsCombinedOK) GetPayload() *models.APIExecutionResultsResponse {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.APIExecutionResultsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowExecutionsCombinedBadRequest creates a WorkflowExecutionsCombinedBadRequest with default headers values
func NewWorkflowExecutionsCombinedBadRequest() *WorkflowExecutionsCombinedBadRequest {
	return &WorkflowExecutionsCombinedBadRequest{}
}

/*
WorkflowExecutionsCombinedBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type WorkflowExecutionsCombinedBadRequest struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIExecutionResultsResponse
}

// IsSuccess returns true when this workflow executions combined bad request response has a 2xx status code
func (o *WorkflowExecutionsCombinedBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow executions combined bad request response has a 3xx status code
func (o *WorkflowExecutionsCombinedBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined bad request response has a 4xx status code
func (o *WorkflowExecutionsCombinedBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow executions combined bad request response has a 5xx status code
func (o *WorkflowExecutionsCombinedBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow executions combined bad request response a status code equal to that given
func (o *WorkflowExecutionsCombinedBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the workflow executions combined bad request response
func (o *WorkflowExecutionsCombinedBadRequest) Code() int {
	return 400
}

func (o *WorkflowExecutionsCombinedBadRequest) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowExecutionsCombinedBadRequest) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedBadRequest  %+v", 400, o.Payload)
}

func (o *WorkflowExecutionsCombinedBadRequest) GetPayload() *models.APIExecutionResultsResponse {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.APIExecutionResultsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowExecutionsCombinedForbidden creates a WorkflowExecutionsCombinedForbidden with default headers values
func NewWorkflowExecutionsCombinedForbidden() *WorkflowExecutionsCombinedForbidden {
	return &WorkflowExecutionsCombinedForbidden{}
}

/*
WorkflowExecutionsCombinedForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type WorkflowExecutionsCombinedForbidden struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this workflow executions combined forbidden response has a 2xx status code
func (o *WorkflowExecutionsCombinedForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow executions combined forbidden response has a 3xx status code
func (o *WorkflowExecutionsCombinedForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined forbidden response has a 4xx status code
func (o *WorkflowExecutionsCombinedForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow executions combined forbidden response has a 5xx status code
func (o *WorkflowExecutionsCombinedForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow executions combined forbidden response a status code equal to that given
func (o *WorkflowExecutionsCombinedForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the workflow executions combined forbidden response
func (o *WorkflowExecutionsCombinedForbidden) Code() int {
	return 403
}

func (o *WorkflowExecutionsCombinedForbidden) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowExecutionsCombinedForbidden) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedForbidden  %+v", 403, o.Payload)
}

func (o *WorkflowExecutionsCombinedForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowExecutionsCombinedNotFound creates a WorkflowExecutionsCombinedNotFound with default headers values
func NewWorkflowExecutionsCombinedNotFound() *WorkflowExecutionsCombinedNotFound {
	return &WorkflowExecutionsCombinedNotFound{}
}

/*
WorkflowExecutionsCombinedNotFound describes a response with status code 404, with default header values.

Not Found
*/
type WorkflowExecutionsCombinedNotFound struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIExecutionResultsResponse
}

// IsSuccess returns true when this workflow executions combined not found response has a 2xx status code
func (o *WorkflowExecutionsCombinedNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow executions combined not found response has a 3xx status code
func (o *WorkflowExecutionsCombinedNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined not found response has a 4xx status code
func (o *WorkflowExecutionsCombinedNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow executions combined not found response has a 5xx status code
func (o *WorkflowExecutionsCombinedNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow executions combined not found response a status code equal to that given
func (o *WorkflowExecutionsCombinedNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the workflow executions combined not found response
func (o *WorkflowExecutionsCombinedNotFound) Code() int {
	return 404
}

func (o *WorkflowExecutionsCombinedNotFound) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowExecutionsCombinedNotFound) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedNotFound  %+v", 404, o.Payload)
}

func (o *WorkflowExecutionsCombinedNotFound) GetPayload() *models.APIExecutionResultsResponse {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.APIExecutionResultsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowExecutionsCombinedTooManyRequests creates a WorkflowExecutionsCombinedTooManyRequests with default headers values
func NewWorkflowExecutionsCombinedTooManyRequests() *WorkflowExecutionsCombinedTooManyRequests {
	return &WorkflowExecutionsCombinedTooManyRequests{}
}

/*
WorkflowExecutionsCombinedTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type WorkflowExecutionsCombinedTooManyRequests struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	/* Too many requests, retry after this time (as milliseconds since epoch)
	 */
	XRateLimitRetryAfter int64

	Payload *models.MsaReplyMetaOnly
}

// IsSuccess returns true when this workflow executions combined too many requests response has a 2xx status code
func (o *WorkflowExecutionsCombinedTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow executions combined too many requests response has a 3xx status code
func (o *WorkflowExecutionsCombinedTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined too many requests response has a 4xx status code
func (o *WorkflowExecutionsCombinedTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this workflow executions combined too many requests response has a 5xx status code
func (o *WorkflowExecutionsCombinedTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this workflow executions combined too many requests response a status code equal to that given
func (o *WorkflowExecutionsCombinedTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the workflow executions combined too many requests response
func (o *WorkflowExecutionsCombinedTooManyRequests) Code() int {
	return 429
}

func (o *WorkflowExecutionsCombinedTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowExecutionsCombinedTooManyRequests) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedTooManyRequests  %+v", 429, o.Payload)
}

func (o *WorkflowExecutionsCombinedTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	// hydrates response header X-RateLimit-RetryAfter
	hdrXRateLimitRetryAfter := response.GetHeader("X-RateLimit-RetryAfter")

	if hdrXRateLimitRetryAfter != "" {
		valxRateLimitRetryAfter, err := swag.ConvertInt64(hdrXRateLimitRetryAfter)
		if err != nil {
			return errors.InvalidType("X-RateLimit-RetryAfter", "header", "int64", hdrXRateLimitRetryAfter)
		}
		o.XRateLimitRetryAfter = valxRateLimitRetryAfter
	}

	o.Payload = new(models.MsaReplyMetaOnly)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWorkflowExecutionsCombinedInternalServerError creates a WorkflowExecutionsCombinedInternalServerError with default headers values
func NewWorkflowExecutionsCombinedInternalServerError() *WorkflowExecutionsCombinedInternalServerError {
	return &WorkflowExecutionsCombinedInternalServerError{}
}

/*
WorkflowExecutionsCombinedInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type WorkflowExecutionsCombinedInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.APIExecutionResultsResponse
}

// IsSuccess returns true when this workflow executions combined internal server error response has a 2xx status code
func (o *WorkflowExecutionsCombinedInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this workflow executions combined internal server error response has a 3xx status code
func (o *WorkflowExecutionsCombinedInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this workflow executions combined internal server error response has a 4xx status code
func (o *WorkflowExecutionsCombinedInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this workflow executions combined internal server error response has a 5xx status code
func (o *WorkflowExecutionsCombinedInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this workflow executions combined internal server error response a status code equal to that given
func (o *WorkflowExecutionsCombinedInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the workflow executions combined internal server error response
func (o *WorkflowExecutionsCombinedInternalServerError) Code() int {
	return 500
}

func (o *WorkflowExecutionsCombinedInternalServerError) Error() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowExecutionsCombinedInternalServerError) String() string {
	return fmt.Sprintf("[GET /workflows/combined/executions/v1][%d] workflowExecutionsCombinedInternalServerError  %+v", 500, o.Payload)
}

func (o *WorkflowExecutionsCombinedInternalServerError) GetPayload() *models.APIExecutionResultsResponse {
	return o.Payload
}

func (o *WorkflowExecutionsCombinedInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header X-CS-TRACEID
	hdrXCSTRACEID := response.GetHeader("X-CS-TRACEID")

	if hdrXCSTRACEID != "" {
		o.XCSTRACEID = hdrXCSTRACEID
	}

	// hydrates response header X-RateLimit-Limit
	hdrXRateLimitLimit := response.GetHeader("X-RateLimit-Limit")

	if hdrXRateLimitLimit != "" {
		valxRateLimitLimit, err := swag.ConvertInt64(hdrXRateLimitLimit)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Limit", "header", "int64", hdrXRateLimitLimit)
		}
		o.XRateLimitLimit = valxRateLimitLimit
	}

	// hydrates response header X-RateLimit-Remaining
	hdrXRateLimitRemaining := response.GetHeader("X-RateLimit-Remaining")

	if hdrXRateLimitRemaining != "" {
		valxRateLimitRemaining, err := swag.ConvertInt64(hdrXRateLimitRemaining)
		if err != nil {
			return errors.InvalidType("X-RateLimit-Remaining", "header", "int64", hdrXRateLimitRemaining)
		}
		o.XRateLimitRemaining = valxRateLimitRemaining
	}

	o.Payload = new(models.APIExecutionResultsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}