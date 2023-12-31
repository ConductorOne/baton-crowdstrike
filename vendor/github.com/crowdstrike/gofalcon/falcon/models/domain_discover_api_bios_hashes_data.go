// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DomainDiscoverAPIBiosHashesData domain discover API bios hashes data
//
// swagger:model domain.DiscoverAPIBiosHashesData
type DomainDiscoverAPIBiosHashesData struct {

	// The measurement type of the associated sha256 hash
	MeasurementType int32 `json:"measurement_type,omitempty"`

	// The sha256 hash from the firmware image
	Sha256Hash string `json:"sha256_hash,omitempty"`
}

// Validate validates this domain discover API bios hashes data
func (m *DomainDiscoverAPIBiosHashesData) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this domain discover API bios hashes data based on context it is used
func (m *DomainDiscoverAPIBiosHashesData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainDiscoverAPIBiosHashesData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainDiscoverAPIBiosHashesData) UnmarshalBinary(b []byte) error {
	var res DomainDiscoverAPIBiosHashesData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
