// Code generated by go-swagger; DO NOT EDIT.

package custom_ioa

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

// NewGetRuleGroupsMixin0Params creates a new GetRuleGroupsMixin0Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetRuleGroupsMixin0Params() *GetRuleGroupsMixin0Params {
	return &GetRuleGroupsMixin0Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetRuleGroupsMixin0ParamsWithTimeout creates a new GetRuleGroupsMixin0Params object
// with the ability to set a timeout on a request.
func NewGetRuleGroupsMixin0ParamsWithTimeout(timeout time.Duration) *GetRuleGroupsMixin0Params {
	return &GetRuleGroupsMixin0Params{
		timeout: timeout,
	}
}

// NewGetRuleGroupsMixin0ParamsWithContext creates a new GetRuleGroupsMixin0Params object
// with the ability to set a context for a request.
func NewGetRuleGroupsMixin0ParamsWithContext(ctx context.Context) *GetRuleGroupsMixin0Params {
	return &GetRuleGroupsMixin0Params{
		Context: ctx,
	}
}

// NewGetRuleGroupsMixin0ParamsWithHTTPClient creates a new GetRuleGroupsMixin0Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetRuleGroupsMixin0ParamsWithHTTPClient(client *http.Client) *GetRuleGroupsMixin0Params {
	return &GetRuleGroupsMixin0Params{
		HTTPClient: client,
	}
}

/*
GetRuleGroupsMixin0Params contains all the parameters to send to the API endpoint

	for the get rule groups mixin0 operation.

	Typically these are written to a http.Request.
*/
type GetRuleGroupsMixin0Params struct {

	/* Ids.

	   The IDs of the entities
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get rule groups mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetRuleGroupsMixin0Params) WithDefaults() *GetRuleGroupsMixin0Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get rule groups mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetRuleGroupsMixin0Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) WithTimeout(timeout time.Duration) *GetRuleGroupsMixin0Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) WithContext(ctx context.Context) *GetRuleGroupsMixin0Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) WithHTTPClient(client *http.Client) *GetRuleGroupsMixin0Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) WithIds(ids []string) *GetRuleGroupsMixin0Params {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get rule groups mixin0 params
func (o *GetRuleGroupsMixin0Params) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetRuleGroupsMixin0Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamGetRuleGroupsMixin0 binds the parameter ids
func (o *GetRuleGroupsMixin0Params) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []string

		idsIIV := idsIIR // string as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "multi"
	idsIS := swag.JoinByFormat(idsIC, "multi")

	return idsIS
}
