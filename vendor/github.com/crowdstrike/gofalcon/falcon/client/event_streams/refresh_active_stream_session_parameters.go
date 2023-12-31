// Code generated by go-swagger; DO NOT EDIT.

package event_streams

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

// NewRefreshActiveStreamSessionParams creates a new RefreshActiveStreamSessionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRefreshActiveStreamSessionParams() *RefreshActiveStreamSessionParams {
	return &RefreshActiveStreamSessionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRefreshActiveStreamSessionParamsWithTimeout creates a new RefreshActiveStreamSessionParams object
// with the ability to set a timeout on a request.
func NewRefreshActiveStreamSessionParamsWithTimeout(timeout time.Duration) *RefreshActiveStreamSessionParams {
	return &RefreshActiveStreamSessionParams{
		timeout: timeout,
	}
}

// NewRefreshActiveStreamSessionParamsWithContext creates a new RefreshActiveStreamSessionParams object
// with the ability to set a context for a request.
func NewRefreshActiveStreamSessionParamsWithContext(ctx context.Context) *RefreshActiveStreamSessionParams {
	return &RefreshActiveStreamSessionParams{
		Context: ctx,
	}
}

// NewRefreshActiveStreamSessionParamsWithHTTPClient creates a new RefreshActiveStreamSessionParams object
// with the ability to set a custom HTTPClient for a request.
func NewRefreshActiveStreamSessionParamsWithHTTPClient(client *http.Client) *RefreshActiveStreamSessionParams {
	return &RefreshActiveStreamSessionParams{
		HTTPClient: client,
	}
}

/*
RefreshActiveStreamSessionParams contains all the parameters to send to the API endpoint

	for the refresh active stream session operation.

	Typically these are written to a http.Request.
*/
type RefreshActiveStreamSessionParams struct {

	/* ActionName.

	   Action name. Allowed value is refresh_active_stream_session.
	*/
	ActionName string

	/* AppID.

	   Label that identifies your connection. Max: 32 alphanumeric characters (a-z, A-Z, 0-9).
	*/
	AppID string

	/* Partition.

	   Partition to request data for.
	*/
	Partition int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the refresh active stream session params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RefreshActiveStreamSessionParams) WithDefaults() *RefreshActiveStreamSessionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the refresh active stream session params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RefreshActiveStreamSessionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithTimeout(timeout time.Duration) *RefreshActiveStreamSessionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithContext(ctx context.Context) *RefreshActiveStreamSessionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithHTTPClient(client *http.Client) *RefreshActiveStreamSessionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithActionName adds the actionName to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithActionName(actionName string) *RefreshActiveStreamSessionParams {
	o.SetActionName(actionName)
	return o
}

// SetActionName adds the actionName to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetActionName(actionName string) {
	o.ActionName = actionName
}

// WithAppID adds the appID to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithAppID(appID string) *RefreshActiveStreamSessionParams {
	o.SetAppID(appID)
	return o
}

// SetAppID adds the appId to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetAppID(appID string) {
	o.AppID = appID
}

// WithPartition adds the partition to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) WithPartition(partition int64) *RefreshActiveStreamSessionParams {
	o.SetPartition(partition)
	return o
}

// SetPartition adds the partition to the refresh active stream session params
func (o *RefreshActiveStreamSessionParams) SetPartition(partition int64) {
	o.Partition = partition
}

// WriteToRequest writes these params to a swagger request
func (o *RefreshActiveStreamSessionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param action_name
	qrActionName := o.ActionName
	qActionName := qrActionName
	if qActionName != "" {

		if err := r.SetQueryParam("action_name", qActionName); err != nil {
			return err
		}
	}

	// query param appId
	qrAppID := o.AppID
	qAppID := qrAppID
	if qAppID != "" {

		if err := r.SetQueryParam("appId", qAppID); err != nil {
			return err
		}
	}

	// path param partition
	if err := r.SetPathParam("partition", swag.FormatInt64(o.Partition)); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
