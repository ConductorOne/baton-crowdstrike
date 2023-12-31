// Code generated by go-swagger; DO NOT EDIT.

package quick_scan

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewQuerySubmissionsMixin0Params creates a new QuerySubmissionsMixin0Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQuerySubmissionsMixin0Params() *QuerySubmissionsMixin0Params {
	return &QuerySubmissionsMixin0Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewQuerySubmissionsMixin0ParamsWithTimeout creates a new QuerySubmissionsMixin0Params object
// with the ability to set a timeout on a request.
func NewQuerySubmissionsMixin0ParamsWithTimeout(timeout time.Duration) *QuerySubmissionsMixin0Params {
	return &QuerySubmissionsMixin0Params{
		timeout: timeout,
	}
}

// NewQuerySubmissionsMixin0ParamsWithContext creates a new QuerySubmissionsMixin0Params object
// with the ability to set a context for a request.
func NewQuerySubmissionsMixin0ParamsWithContext(ctx context.Context) *QuerySubmissionsMixin0Params {
	return &QuerySubmissionsMixin0Params{
		Context: ctx,
	}
}

// NewQuerySubmissionsMixin0ParamsWithHTTPClient creates a new QuerySubmissionsMixin0Params object
// with the ability to set a custom HTTPClient for a request.
func NewQuerySubmissionsMixin0ParamsWithHTTPClient(client *http.Client) *QuerySubmissionsMixin0Params {
	return &QuerySubmissionsMixin0Params{
		HTTPClient: client,
	}
}

/*
QuerySubmissionsMixin0Params contains all the parameters to send to the API endpoint

	for the query submissions mixin0 operation.

	Typically these are written to a http.Request.
*/
type QuerySubmissionsMixin0Params struct {

	/* Filter.

	   Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).
	*/
	Filter *string

	/* Limit.

	   Maximum number of volume IDs to return. Max: 5000.
	*/
	Limit *int64

	/* Offset.

	   The offset to start retrieving submissions from.
	*/
	Offset *string

	/* Sort.

	   Sort order: `asc` or `desc`.
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query submissions mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QuerySubmissionsMixin0Params) WithDefaults() *QuerySubmissionsMixin0Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query submissions mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QuerySubmissionsMixin0Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithTimeout(timeout time.Duration) *QuerySubmissionsMixin0Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithContext(ctx context.Context) *QuerySubmissionsMixin0Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithHTTPClient(client *http.Client) *QuerySubmissionsMixin0Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithFilter(filter *string) *QuerySubmissionsMixin0Params {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithLimit(limit *int64) *QuerySubmissionsMixin0Params {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithOffset(offset *string) *QuerySubmissionsMixin0Params {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetOffset(offset *string) {
	o.Offset = offset
}

// WithSort adds the sort to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) WithSort(sort *string) *QuerySubmissionsMixin0Params {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the query submissions mixin0 params
func (o *QuerySubmissionsMixin0Params) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *QuerySubmissionsMixin0Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset string

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := qrOffset
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
