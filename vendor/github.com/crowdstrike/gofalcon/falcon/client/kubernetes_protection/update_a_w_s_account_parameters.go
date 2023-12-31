// Code generated by go-swagger; DO NOT EDIT.

package kubernetes_protection

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

// NewUpdateAWSAccountParams creates a new UpdateAWSAccountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateAWSAccountParams() *UpdateAWSAccountParams {
	return &UpdateAWSAccountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateAWSAccountParamsWithTimeout creates a new UpdateAWSAccountParams object
// with the ability to set a timeout on a request.
func NewUpdateAWSAccountParamsWithTimeout(timeout time.Duration) *UpdateAWSAccountParams {
	return &UpdateAWSAccountParams{
		timeout: timeout,
	}
}

// NewUpdateAWSAccountParamsWithContext creates a new UpdateAWSAccountParams object
// with the ability to set a context for a request.
func NewUpdateAWSAccountParamsWithContext(ctx context.Context) *UpdateAWSAccountParams {
	return &UpdateAWSAccountParams{
		Context: ctx,
	}
}

// NewUpdateAWSAccountParamsWithHTTPClient creates a new UpdateAWSAccountParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateAWSAccountParamsWithHTTPClient(client *http.Client) *UpdateAWSAccountParams {
	return &UpdateAWSAccountParams{
		HTTPClient: client,
	}
}

/*
UpdateAWSAccountParams contains all the parameters to send to the API endpoint

	for the update a w s account operation.

	Typically these are written to a http.Request.
*/
type UpdateAWSAccountParams struct {

	/* Ids.

	   AWS Account ID
	*/
	Ids []string

	/* Region.

	   Default Region for Account Automation
	*/
	Region *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update a w s account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateAWSAccountParams) WithDefaults() *UpdateAWSAccountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update a w s account params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateAWSAccountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update a w s account params
func (o *UpdateAWSAccountParams) WithTimeout(timeout time.Duration) *UpdateAWSAccountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update a w s account params
func (o *UpdateAWSAccountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update a w s account params
func (o *UpdateAWSAccountParams) WithContext(ctx context.Context) *UpdateAWSAccountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update a w s account params
func (o *UpdateAWSAccountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update a w s account params
func (o *UpdateAWSAccountParams) WithHTTPClient(client *http.Client) *UpdateAWSAccountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update a w s account params
func (o *UpdateAWSAccountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the update a w s account params
func (o *UpdateAWSAccountParams) WithIds(ids []string) *UpdateAWSAccountParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the update a w s account params
func (o *UpdateAWSAccountParams) SetIds(ids []string) {
	o.Ids = ids
}

// WithRegion adds the region to the update a w s account params
func (o *UpdateAWSAccountParams) WithRegion(region *string) *UpdateAWSAccountParams {
	o.SetRegion(region)
	return o
}

// SetRegion adds the region to the update a w s account params
func (o *UpdateAWSAccountParams) SetRegion(region *string) {
	o.Region = region
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateAWSAccountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if o.Region != nil {

		// query param region
		var qrRegion string

		if o.Region != nil {
			qrRegion = *o.Region
		}
		qRegion := qrRegion
		if qRegion != "" {

			if err := r.SetQueryParam("region", qRegion); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamUpdateAWSAccount binds the parameter ids
func (o *UpdateAWSAccountParams) bindParamIds(formats strfmt.Registry) []string {
	idsIR := o.Ids

	var idsIC []string
	for _, idsIIR := range idsIR { // explode []string

		idsIIV := idsIIR // string as string
		idsIC = append(idsIC, idsIIV)
	}

	// items.CollectionFormat: "csv"
	idsIS := swag.JoinByFormat(idsIC, "csv")

	return idsIS
}
