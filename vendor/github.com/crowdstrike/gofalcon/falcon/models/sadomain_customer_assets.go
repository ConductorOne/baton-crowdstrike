// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SadomainCustomerAssets sadomain customer assets
//
// swagger:model sadomain.CustomerAssets
type SadomainCustomerAssets struct {

	// domains
	Domains []string `json:"domains"`

	// emails
	Emails []string `json:"emails"`
}

// Validate validates this sadomain customer assets
func (m *SadomainCustomerAssets) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this sadomain customer assets based on context it is used
func (m *SadomainCustomerAssets) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SadomainCustomerAssets) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SadomainCustomerAssets) UnmarshalBinary(b []byte) error {
	var res SadomainCustomerAssets
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
