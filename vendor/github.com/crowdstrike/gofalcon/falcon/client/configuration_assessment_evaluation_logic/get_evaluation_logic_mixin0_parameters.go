// Code generated by go-swagger; DO NOT EDIT.

package configuration_assessment_evaluation_logic

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

// NewGetEvaluationLogicMixin0Params creates a new GetEvaluationLogicMixin0Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetEvaluationLogicMixin0Params() *GetEvaluationLogicMixin0Params {
	return &GetEvaluationLogicMixin0Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetEvaluationLogicMixin0ParamsWithTimeout creates a new GetEvaluationLogicMixin0Params object
// with the ability to set a timeout on a request.
func NewGetEvaluationLogicMixin0ParamsWithTimeout(timeout time.Duration) *GetEvaluationLogicMixin0Params {
	return &GetEvaluationLogicMixin0Params{
		timeout: timeout,
	}
}

// NewGetEvaluationLogicMixin0ParamsWithContext creates a new GetEvaluationLogicMixin0Params object
// with the ability to set a context for a request.
func NewGetEvaluationLogicMixin0ParamsWithContext(ctx context.Context) *GetEvaluationLogicMixin0Params {
	return &GetEvaluationLogicMixin0Params{
		Context: ctx,
	}
}

// NewGetEvaluationLogicMixin0ParamsWithHTTPClient creates a new GetEvaluationLogicMixin0Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetEvaluationLogicMixin0ParamsWithHTTPClient(client *http.Client) *GetEvaluationLogicMixin0Params {
	return &GetEvaluationLogicMixin0Params{
		HTTPClient: client,
	}
}

/*
GetEvaluationLogicMixin0Params contains all the parameters to send to the API endpoint

	for the get evaluation logic mixin0 operation.

	Typically these are written to a http.Request.
*/
type GetEvaluationLogicMixin0Params struct {

	/* Ids.

	   One or more evaluation logic finding IDs.
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get evaluation logic mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetEvaluationLogicMixin0Params) WithDefaults() *GetEvaluationLogicMixin0Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get evaluation logic mixin0 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetEvaluationLogicMixin0Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) WithTimeout(timeout time.Duration) *GetEvaluationLogicMixin0Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) WithContext(ctx context.Context) *GetEvaluationLogicMixin0Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) WithHTTPClient(client *http.Client) *GetEvaluationLogicMixin0Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) WithIds(ids []string) *GetEvaluationLogicMixin0Params {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the get evaluation logic mixin0 params
func (o *GetEvaluationLogicMixin0Params) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *GetEvaluationLogicMixin0Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamGetEvaluationLogicMixin0 binds the parameter ids
func (o *GetEvaluationLogicMixin0Params) bindParamIds(formats strfmt.Registry) []string {
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