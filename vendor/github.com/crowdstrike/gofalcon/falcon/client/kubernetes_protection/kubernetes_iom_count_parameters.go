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
)

// NewKubernetesIomCountParams creates a new KubernetesIomCountParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewKubernetesIomCountParams() *KubernetesIomCountParams {
	return &KubernetesIomCountParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewKubernetesIomCountParamsWithTimeout creates a new KubernetesIomCountParams object
// with the ability to set a timeout on a request.
func NewKubernetesIomCountParamsWithTimeout(timeout time.Duration) *KubernetesIomCountParams {
	return &KubernetesIomCountParams{
		timeout: timeout,
	}
}

// NewKubernetesIomCountParamsWithContext creates a new KubernetesIomCountParams object
// with the ability to set a context for a request.
func NewKubernetesIomCountParamsWithContext(ctx context.Context) *KubernetesIomCountParams {
	return &KubernetesIomCountParams{
		Context: ctx,
	}
}

// NewKubernetesIomCountParamsWithHTTPClient creates a new KubernetesIomCountParams object
// with the ability to set a custom HTTPClient for a request.
func NewKubernetesIomCountParamsWithHTTPClient(client *http.Client) *KubernetesIomCountParams {
	return &KubernetesIomCountParams{
		HTTPClient: client,
	}
}

/*
KubernetesIomCountParams contains all the parameters to send to the API endpoint

	for the kubernetes iom count operation.

	Typically these are written to a http.Request.
*/
type KubernetesIomCountParams struct {

	/* Filter.

	   Filter images using a query in Falcon Query Language (FQL). Supported filters: cid,created_timestamp,detect_timestamp,prevented,severity
	*/
	Filter *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the kubernetes iom count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *KubernetesIomCountParams) WithDefaults() *KubernetesIomCountParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the kubernetes iom count params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *KubernetesIomCountParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the kubernetes iom count params
func (o *KubernetesIomCountParams) WithTimeout(timeout time.Duration) *KubernetesIomCountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the kubernetes iom count params
func (o *KubernetesIomCountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the kubernetes iom count params
func (o *KubernetesIomCountParams) WithContext(ctx context.Context) *KubernetesIomCountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the kubernetes iom count params
func (o *KubernetesIomCountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the kubernetes iom count params
func (o *KubernetesIomCountParams) WithHTTPClient(client *http.Client) *KubernetesIomCountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the kubernetes iom count params
func (o *KubernetesIomCountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the kubernetes iom count params
func (o *KubernetesIomCountParams) WithFilter(filter *string) *KubernetesIomCountParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the kubernetes iom count params
func (o *KubernetesIomCountParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WriteToRequest writes these params to a swagger request
func (o *KubernetesIomCountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}