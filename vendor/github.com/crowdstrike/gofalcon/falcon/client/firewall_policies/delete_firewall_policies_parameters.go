// Code generated by go-swagger; DO NOT EDIT.

package firewall_policies

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

// NewDeleteFirewallPoliciesParams creates a new DeleteFirewallPoliciesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteFirewallPoliciesParams() *DeleteFirewallPoliciesParams {
	return &DeleteFirewallPoliciesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteFirewallPoliciesParamsWithTimeout creates a new DeleteFirewallPoliciesParams object
// with the ability to set a timeout on a request.
func NewDeleteFirewallPoliciesParamsWithTimeout(timeout time.Duration) *DeleteFirewallPoliciesParams {
	return &DeleteFirewallPoliciesParams{
		timeout: timeout,
	}
}

// NewDeleteFirewallPoliciesParamsWithContext creates a new DeleteFirewallPoliciesParams object
// with the ability to set a context for a request.
func NewDeleteFirewallPoliciesParamsWithContext(ctx context.Context) *DeleteFirewallPoliciesParams {
	return &DeleteFirewallPoliciesParams{
		Context: ctx,
	}
}

// NewDeleteFirewallPoliciesParamsWithHTTPClient creates a new DeleteFirewallPoliciesParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteFirewallPoliciesParamsWithHTTPClient(client *http.Client) *DeleteFirewallPoliciesParams {
	return &DeleteFirewallPoliciesParams{
		HTTPClient: client,
	}
}

/*
DeleteFirewallPoliciesParams contains all the parameters to send to the API endpoint

	for the delete firewall policies operation.

	Typically these are written to a http.Request.
*/
type DeleteFirewallPoliciesParams struct {

	/* Ids.

	   The IDs of the Firewall Policies to delete
	*/
	Ids []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete firewall policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteFirewallPoliciesParams) WithDefaults() *DeleteFirewallPoliciesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete firewall policies params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteFirewallPoliciesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) WithTimeout(timeout time.Duration) *DeleteFirewallPoliciesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) WithContext(ctx context.Context) *DeleteFirewallPoliciesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) WithHTTPClient(client *http.Client) *DeleteFirewallPoliciesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIds adds the ids to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) WithIds(ids []string) *DeleteFirewallPoliciesParams {
	o.SetIds(ids)
	return o
}

// SetIds adds the ids to the delete firewall policies params
func (o *DeleteFirewallPoliciesParams) SetIds(ids []string) {
	o.Ids = ids
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteFirewallPoliciesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

// bindParamDeleteFirewallPolicies binds the parameter ids
func (o *DeleteFirewallPoliciesParams) bindParamIds(formats strfmt.Registry) []string {
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
