// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// APIPostEnrollmentDetails api post enrollment details
//
// swagger:model api.postEnrollmentDetails
type APIPostEnrollmentDetails struct {

	// email addresses
	// Required: true
	EmailAddresses []string `json:"email_addresses"`

	// expires at
	// Required: true
	// Format: date-time
	ExpiresAt *strfmt.DateTime `json:"expires_at"`
}

// Validate validates this api post enrollment details
func (m *APIPostEnrollmentDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmailAddresses(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIPostEnrollmentDetails) validateEmailAddresses(formats strfmt.Registry) error {

	if err := validate.Required("email_addresses", "body", m.EmailAddresses); err != nil {
		return err
	}

	return nil
}

func (m *APIPostEnrollmentDetails) validateExpiresAt(formats strfmt.Registry) error {

	if err := validate.Required("expires_at", "body", m.ExpiresAt); err != nil {
		return err
	}

	if err := validate.FormatOf("expires_at", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this api post enrollment details based on context it is used
func (m *APIPostEnrollmentDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIPostEnrollmentDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIPostEnrollmentDetails) UnmarshalBinary(b []byte) error {
	var res APIPostEnrollmentDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
