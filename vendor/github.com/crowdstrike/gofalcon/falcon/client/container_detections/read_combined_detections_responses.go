// Code generated by go-swagger; DO NOT EDIT.

package container_detections

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

// ReadCombinedDetectionsReader is a Reader for the ReadCombinedDetections structure.
type ReadCombinedDetectionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ReadCombinedDetectionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewReadCombinedDetectionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 403:
		result := NewReadCombinedDetectionsForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewReadCombinedDetectionsTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewReadCombinedDetectionsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /container-security/combined/detections/v1] ReadCombinedDetections", response, response.Code())
	}
}

// NewReadCombinedDetectionsOK creates a ReadCombinedDetectionsOK with default headers values
func NewReadCombinedDetectionsOK() *ReadCombinedDetectionsOK {
	return &ReadCombinedDetectionsOK{}
}

/*
ReadCombinedDetectionsOK describes a response with status code 200, with default header values.

OK
*/
type ReadCombinedDetectionsOK struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.DetectionsAPICombinedDetections
}

// IsSuccess returns true when this read combined detections o k response has a 2xx status code
func (o *ReadCombinedDetectionsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this read combined detections o k response has a 3xx status code
func (o *ReadCombinedDetectionsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read combined detections o k response has a 4xx status code
func (o *ReadCombinedDetectionsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this read combined detections o k response has a 5xx status code
func (o *ReadCombinedDetectionsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this read combined detections o k response a status code equal to that given
func (o *ReadCombinedDetectionsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the read combined detections o k response
func (o *ReadCombinedDetectionsOK) Code() int {
	return 200
}

func (o *ReadCombinedDetectionsOK) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsOK  %+v", 200, o.Payload)
}

func (o *ReadCombinedDetectionsOK) String() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsOK  %+v", 200, o.Payload)
}

func (o *ReadCombinedDetectionsOK) GetPayload() *models.DetectionsAPICombinedDetections {
	return o.Payload
}

func (o *ReadCombinedDetectionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.DetectionsAPICombinedDetections)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewReadCombinedDetectionsForbidden creates a ReadCombinedDetectionsForbidden with default headers values
func NewReadCombinedDetectionsForbidden() *ReadCombinedDetectionsForbidden {
	return &ReadCombinedDetectionsForbidden{}
}

/*
ReadCombinedDetectionsForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ReadCombinedDetectionsForbidden struct {

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

// IsSuccess returns true when this read combined detections forbidden response has a 2xx status code
func (o *ReadCombinedDetectionsForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read combined detections forbidden response has a 3xx status code
func (o *ReadCombinedDetectionsForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read combined detections forbidden response has a 4xx status code
func (o *ReadCombinedDetectionsForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this read combined detections forbidden response has a 5xx status code
func (o *ReadCombinedDetectionsForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this read combined detections forbidden response a status code equal to that given
func (o *ReadCombinedDetectionsForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the read combined detections forbidden response
func (o *ReadCombinedDetectionsForbidden) Code() int {
	return 403
}

func (o *ReadCombinedDetectionsForbidden) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsForbidden  %+v", 403, o.Payload)
}

func (o *ReadCombinedDetectionsForbidden) String() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsForbidden  %+v", 403, o.Payload)
}

func (o *ReadCombinedDetectionsForbidden) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadCombinedDetectionsForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadCombinedDetectionsTooManyRequests creates a ReadCombinedDetectionsTooManyRequests with default headers values
func NewReadCombinedDetectionsTooManyRequests() *ReadCombinedDetectionsTooManyRequests {
	return &ReadCombinedDetectionsTooManyRequests{}
}

/*
ReadCombinedDetectionsTooManyRequests describes a response with status code 429, with default header values.

Too Many Requests
*/
type ReadCombinedDetectionsTooManyRequests struct {

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

// IsSuccess returns true when this read combined detections too many requests response has a 2xx status code
func (o *ReadCombinedDetectionsTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read combined detections too many requests response has a 3xx status code
func (o *ReadCombinedDetectionsTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read combined detections too many requests response has a 4xx status code
func (o *ReadCombinedDetectionsTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this read combined detections too many requests response has a 5xx status code
func (o *ReadCombinedDetectionsTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this read combined detections too many requests response a status code equal to that given
func (o *ReadCombinedDetectionsTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the read combined detections too many requests response
func (o *ReadCombinedDetectionsTooManyRequests) Code() int {
	return 429
}

func (o *ReadCombinedDetectionsTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadCombinedDetectionsTooManyRequests) String() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsTooManyRequests  %+v", 429, o.Payload)
}

func (o *ReadCombinedDetectionsTooManyRequests) GetPayload() *models.MsaReplyMetaOnly {
	return o.Payload
}

func (o *ReadCombinedDetectionsTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewReadCombinedDetectionsInternalServerError creates a ReadCombinedDetectionsInternalServerError with default headers values
func NewReadCombinedDetectionsInternalServerError() *ReadCombinedDetectionsInternalServerError {
	return &ReadCombinedDetectionsInternalServerError{}
}

/*
ReadCombinedDetectionsInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type ReadCombinedDetectionsInternalServerError struct {

	/* Trace-ID: submit to support if resolving an issue
	 */
	XCSTRACEID string

	/* Request limit per minute.
	 */
	XRateLimitLimit int64

	/* The number of requests remaining for the sliding one minute window.
	 */
	XRateLimitRemaining int64

	Payload *models.CoreEntitiesResponse
}

// IsSuccess returns true when this read combined detections internal server error response has a 2xx status code
func (o *ReadCombinedDetectionsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this read combined detections internal server error response has a 3xx status code
func (o *ReadCombinedDetectionsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this read combined detections internal server error response has a 4xx status code
func (o *ReadCombinedDetectionsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this read combined detections internal server error response has a 5xx status code
func (o *ReadCombinedDetectionsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this read combined detections internal server error response a status code equal to that given
func (o *ReadCombinedDetectionsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the read combined detections internal server error response
func (o *ReadCombinedDetectionsInternalServerError) Code() int {
	return 500
}

func (o *ReadCombinedDetectionsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadCombinedDetectionsInternalServerError) String() string {
	return fmt.Sprintf("[GET /container-security/combined/detections/v1][%d] readCombinedDetectionsInternalServerError  %+v", 500, o.Payload)
}

func (o *ReadCombinedDetectionsInternalServerError) GetPayload() *models.CoreEntitiesResponse {
	return o.Payload
}

func (o *ReadCombinedDetectionsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

	o.Payload = new(models.CoreEntitiesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}