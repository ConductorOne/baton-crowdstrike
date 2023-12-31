// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainDiscoverAPIFieldMetadata The metadata information for a host for each field
//
// swagger:model domain.DiscoverAPIFieldMetadata
type DomainDiscoverAPIFieldMetadata struct {

	// Providers which have set the value.
	Providers []string `json:"providers"`
}

// Validate validates this domain discover API field metadata
func (m *DomainDiscoverAPIFieldMetadata) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain discover API field metadata based on context it is used
func (m *DomainDiscoverAPIFieldMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainDiscoverAPIFieldMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDiscoverAPIFieldMetadata) UnmarshalBinary(b []byte) error {
	var res DomainDiscoverAPIFieldMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
