// Code generated by go-swagger; DO NOT EDIT.

package cspm_registration

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

// NewGetCSPMPoliciesDetailsParams creates a new GetCSPMPoliciesDetailsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCSPMPoliciesDetailsParams() *GetCSPMPoliciesDetailsParams {
	return &GetCSPMPoliciesDetailsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCSPMPoliciesDetailsParamsWithTimeout creates a new GetCSPMPoliciesDetailsParams object
// with the ability to set a timeout on a request.
func NewGetCSPMPoliciesDetailsParamsWithTimeout(timeout time.Duration) *GetCSPMPoliciesDetailsParams {
	return &GetCSPMPoliciesDetailsParams{
		timeout: timeout,
	}
}

// NewGetCSPMPoliciesDetailsParamsWithContext creates a new GetCSPMPoliciesDetailsParams object
// with the ability to set a context for a request.
func NewGetCSPMPoliciesDetailsParamsWithContext(ctx context.Context) *GetCSPMPoliciesDetailsParams {
	return &GetCSPMPoliciesDetailsParams{
		Context: ctx,
	}
}

// NewGetCSPMPoliciesDetailsParamsWithHTTPClient creates a new GetCSPMPoliciesDetailsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCSPMPoliciesDetailsParamsWithHTTPClient(client *http.Client) *GetCSPMPoliciesDetailsParams {
	return &GetCSPMPoliciesDetailsParams{
		HTTPClient: client,
	}
}

/*
GetCSPMPoliciesDetailsParams contains all the parameters to send to the API endpoint

	for the get c s p m policies details operation.

	Typically these are written to a http.Request.
*/
type GetCSPMPoliciesDetailsParams struct {

	/* Ids.

	   Policy IDs
	*/
	Ids []int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c s p m policies details params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMPoliciesDetailsParams) WithDefaults() *GetCSPMPoliciesDetailsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c s p m policies details params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCSPMPoliciesDetailsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) WithTimeout(timeout time.Duration) *GetCSPMPoliciesDetailsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) WithContext(ctx context.Context) *GetCSPMPoliciesDetailsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) WithHTTPClient(client *http.Client) *GetCSPMPoliciesDetailsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) WithIds(ids []int64) *GetCSPMPoliciesDetailsParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get c s p m policies details params
func (o *GetCSPMPoliciesDetailsParams) SetIds(ids []int64) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetCSPMPoliciesDetailsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Ids != nil {

		// binding items for ids
		joinedIds := o.bindParamIds(reg)

		// query array param ids
		if err := r.SetQueryParam("ids", joinedIds...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamGetCSPMPoliciesDetails binds the parameter ids
func (o *GetCSPMPoliciesDetailsParams) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []int64

		idsIIV := swag.FormatInt64(idsIIR) // int64 as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "multi"
	idsIS := swag.JoinByFormat(idsIC, "multi")

	return idsIS
}
