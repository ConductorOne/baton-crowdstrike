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

// NewAzureDownloadCertificateParams creates a new AzureDownloadCertificateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAzureDownloadCertificateParams() *AzureDownloadCertificateParams {
	return &AzureDownloadCertificateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAzureDownloadCertificateParamsWithTimeout creates a new AzureDownloadCertificateParams object
// with the ability to set a timeout on a request.
func NewAzureDownloadCertificateParamsWithTimeout(timeout time.Duration) *AzureDownloadCertificateParams {
	return &AzureDownloadCertificateParams{
		timeout: timeout,
	}
}

// NewAzureDownloadCertificateParamsWithContext creates a new AzureDownloadCertificateParams object
// with the ability to set a context for a request.
func NewAzureDownloadCertificateParamsWithContext(ctx context.Context) *AzureDownloadCertificateParams {
	return &AzureDownloadCertificateParams{
		Context: ctx,
	}
}

// NewAzureDownloadCertificateParamsWithHTTPClient creates a new AzureDownloadCertificateParams object
// with the ability to set a custom HTTPClient for a request.
func NewAzureDownloadCertificateParamsWithHTTPClient(client *http.Client) *AzureDownloadCertificateParams {
	return &AzureDownloadCertificateParams{
		HTTPClient: client,
	}
}

/*
AzureDownloadCertificateParams contains all the parameters to send to the API endpoint

	for the azure download certificate operation.

	Typically these are written to a http.Request.
*/
type AzureDownloadCertificateParams struct {

	/* Refresh.

	   Setting to true will invalidate the current certificate and generate a new certificate
	*/
	Refresh *bool

	/* TenantID.

	   Azure Tenant ID
	*/
	TenantID []string

	/* YearsValid.

	   Years the certificate should be valid (only used when refresh=true)
	*/
	YearsValid *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the azure download certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AzureDownloadCertificateParams) WithDefaults() *AzureDownloadCertificateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the azure download certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AzureDownloadCertificateParams) SetDefaults() {
	var (
		refreshDefault = bool(false)
	)

	val := AzureDownloadCertificateParams{
		Refresh: &refreshDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithTimeout(timeout time.Duration) *AzureDownloadCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithContext(ctx context.Context) *AzureDownloadCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithHTTPClient(client *http.Client) *AzureDownloadCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRefresh adds the refresh to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithRefresh(refresh *bool) *AzureDownloadCertificateParams {
	o.SetRefresh(refresh)
	return o
}

// SetRefresh adds the refresh to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetRefresh(refresh *bool) {
	o.Refresh = refresh
}

// WithTenantID adds the tenantID to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithTenantID(tenantID []string) *AzureDownloadCertificateParams {
	o.SetTenantID(tenantID)
	return o
}

// SetTenantID adds the tenantId to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetTenantID(tenantID []string) {
	o.TenantID = tenantID
}

// WithYearsValid adds the yearsValid to the azure download certificate params
func (o *AzureDownloadCertificateParams) WithYearsValid(yearsValid *string) *AzureDownloadCertificateParams {
	o.SetYearsValid(yearsValid)
	return o
}

// SetYearsValid adds the yearsValid to the azure download certificate params
func (o *AzureDownloadCertificateParams) SetYearsValid(yearsValid *string) {
	o.YearsValid = yearsValid
}

// WriteToRequest writes these params to a swagger request
func (o *AzureDownloadCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Refresh != nil {

		// query param refresh
		var qrRefresh bool

		if o.Refresh != nil {
			qrRefresh = *o.Refresh
		}
		qRefresh := swag.FormatBool(qrRefresh)
		if qRefresh != "" {

			if err := r.SetQueryParam("refresh", qRefresh); err != nil {
				return err
			}
		}
	}

	if o.TenantID != nil {

		// binding items for tenant_id
		joinedTenantID := o.bindParamTenantID(reg)

		// query array param tenant_id
		if err := r.SetQueryParam("tenant_id", joinedTenantID...); err != nil {
			return err
		}
	}

	if o.YearsValid != nil {

		// query param years_valid
		var qrYearsValid string

		if o.YearsValid != nil {
			qrYearsValid = *o.YearsValid
		}
		qYearsValid := qrYearsValid
		if qYearsValid != "" {

			if err := r.SetQueryParam("years_valid", qYearsValid); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamAzureDownloadCertificate binds the parameter tenant_id
func (o *AzureDownloadCertificateParams) bindParamTenantID(formats strfmt.Registry) []string {
	tenantIDIR := o.TenantID

	var tenantIDIC []string
	for _, tenantIDIIR := range tenantIDIR { // explode []string

		tenantIDIIV := tenantIDIIR // string as string
		tenantIDIC = append(tenantIDIC, tenantIDIIV)
	}

	// items.CollectionFormat: "multi"
	tenantIDIS := swag.JoinByFormat(tenantIDIC, "multi")

	return tenantIDIS
}
