// Code generated by go-swagger; DO NOT EDIT.

package alerts

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

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// NewGetAggregateV2Params creates a new GetAggregateV2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAggregateV2Params() *GetAggregateV2Params {
	return &GetAggregateV2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAggregateV2ParamsWithTimeout creates a new GetAggregateV2Params object
// with the ability to set a timeout on a request.
func NewGetAggregateV2ParamsWithTimeout(timeout time.Duration) *GetAggregateV2Params {
	return &GetAggregateV2Params{
		timeout: timeout,
	}
}

// NewGetAggregateV2ParamsWithContext creates a new GetAggregateV2Params object
// with the ability to set a context for a request.
func NewGetAggregateV2ParamsWithContext(ctx context.Context) *GetAggregateV2Params {
	return &GetAggregateV2Params{
		Context: ctx,
	}
}

// NewGetAggregateV2ParamsWithHTTPClient creates a new GetAggregateV2Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetAggregateV2ParamsWithHTTPClient(client *http.Client) *GetAggregateV2Params {
	return &GetAggregateV2Params{
		HTTPClient: client,
	}
}

/*
GetAggregateV2Params contains all the parameters to send to the API endpoint

	for the get aggregate v2 operation.

	Typically these are written to a http.Request.
*/
type GetAggregateV2Params struct {

	/* Body.

	   request body takes a list of aggregate-alert query requests
	*/
	Body []*models.DetectsapiAggregateAlertQueryRequest

	/* IncludeHidden.

	   allows previously hidden alerts to be retrieved

	   Default: true
	*/
	IncludeHidden *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get aggregate v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAggregateV2Params) WithDefaults() *GetAggregateV2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get aggregate v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAggregateV2Params) SetDefaults() {
	var (
		includeHiddenDefault = bool(true)
	)

	val := GetAggregateV2Params{
		IncludeHidden: &includeHiddenDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get aggregate v2 params
func (o *GetAggregateV2Params) WithTimeout(timeout time.Duration) *GetAggregateV2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get aggregate v2 params
func (o *GetAggregateV2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get aggregate v2 params
func (o *GetAggregateV2Params) WithContext(ctx context.Context) *GetAggregateV2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get aggregate v2 params
func (o *GetAggregateV2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get aggregate v2 params
func (o *GetAggregateV2Params) WithHTTPClient(client *http.Client) *GetAggregateV2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get aggregate v2 params
func (o *GetAggregateV2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get aggregate v2 params
func (o *GetAggregateV2Params) WithBody(body []*models.DetectsapiAggregateAlertQueryRequest) *GetAggregateV2Params {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get aggregate v2 params
func (o *GetAggregateV2Params) SetBody(body []*models.DetectsapiAggregateAlertQueryRequest) {
	o.Body = body
}

// WithIncludeHidden adds the includeHidden to the get aggregate v2 params
func (o *GetAggregateV2Params) WithIncludeHidden(includeHidden *bool) *GetAggregateV2Params {
	o.SetIncludeHidden(includeHidden)
	return o
}

// SetIncludeHidden adds the includeHidden to the get aggregate v2 params
func (o *GetAggregateV2Params) SetIncludeHidden(includeHidden *bool) {
	o.IncludeHidden = includeHidden
}

// WriteToRequest writes these params to a swagger request
func (o *GetAggregateV2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if o.IncludeHidden != nil {

		// query param include_hidden
		var qrIncludeHidden bool

		if o.IncludeHidden != nil {
			qrIncludeHidden = *o.IncludeHidden
		}
		qIncludeHidden := swag.FormatBool(qrIncludeHidden)
		if qIncludeHidden != "" {

			if err := r.SetQueryParam("include_hidden", qIncludeHidden); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}