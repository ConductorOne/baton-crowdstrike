// Code generated by go-swagger; DO NOT EDIT.

package falcon_complete_dashboard

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

// NewGetDeviceCountCollectionQueriesByFilterParams creates a new GetDeviceCountCollectionQueriesByFilterParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDeviceCountCollectionQueriesByFilterParams() *GetDeviceCountCollectionQueriesByFilterParams {
	return &GetDeviceCountCollectionQueriesByFilterParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDeviceCountCollectionQueriesByFilterParamsWithTimeout creates a new GetDeviceCountCollectionQueriesByFilterParams object
// with the ability to set a timeout on a request.
func NewGetDeviceCountCollectionQueriesByFilterParamsWithTimeout(timeout time.Duration) *GetDeviceCountCollectionQueriesByFilterParams {
	return &GetDeviceCountCollectionQueriesByFilterParams{
		timeout: timeout,
	}
}

// NewGetDeviceCountCollectionQueriesByFilterParamsWithContext creates a new GetDeviceCountCollectionQueriesByFilterParams object
// with the ability to set a context for a request.
func NewGetDeviceCountCollectionQueriesByFilterParamsWithContext(ctx context.Context) *GetDeviceCountCollectionQueriesByFilterParams {
	return &GetDeviceCountCollectionQueriesByFilterParams{
		Context: ctx,
	}
}

// NewGetDeviceCountCollectionQueriesByFilterParamsWithHTTPClient creates a new GetDeviceCountCollectionQueriesByFilterParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDeviceCountCollectionQueriesByFilterParamsWithHTTPClient(client *http.Client) *GetDeviceCountCollectionQueriesByFilterParams {
	return &GetDeviceCountCollectionQueriesByFilterParams{
		HTTPClient: client,
	}
}

/*
GetDeviceCountCollectionQueriesByFilterParams contains all the parameters to send to the API endpoint

	for the get device count collection queries by filter operation.

	Typically these are written to a http.Request.
*/
type GetDeviceCountCollectionQueriesByFilterParams struct {

	/* Filter.

	   Optional filter and sort criteria in the form of an FQL query. For more information about FQL queries, see [our FQL documentation in Falcon](https://falcon.crowdstrike.com/support/documentation/45/falcon-query-language-feature-guide).
	*/
	Filter *string

	/* Limit.

	   The maximum records to return. [1-500]
	*/
	Limit *int64

	/* Offset.

	   Starting index of overall result set from which to return ids.
	*/
	Offset *string

	/* Sort.

	   The property to sort on, followed by a dot (.), followed by the sort direction, either "asc" or "desc".
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get device count collection queries by filter params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithDefaults() *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get device count collection queries by filter params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithTimeout(timeout time.Duration) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithContext(ctx context.Context) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithHTTPClient(client *http.Client) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithFilter(filter *string) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithLimit(limit *int64) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithOffset(offset *string) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetOffset(offset *string) {
	o.Offset = offset
}

// WithSort adds the sort to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) WithSort(sort *string) *GetDeviceCountCollectionQueriesByFilterParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get device count collection queries by filter params
func (o *GetDeviceCountCollectionQueriesByFilterParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetDeviceCountCollectionQueriesByFilterParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
