// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// FalconxC2 falconx c2
//
// swagger:model falconx.C2
type FalconxC2 struct {

	// host
	Host string `json:"host,omitempty"`

	// path
	Path string `json:"path,omitempty"`

	// port
	Port int32 `json:"port,omitempty"`

	// protocol
	Protocol string `json:"protocol,omitempty"`
}

// Validate validates this falconx c2
func (m *FalconxC2) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this falconx c2 based on context it is used
func (m *FalconxC2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FalconxC2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FalconxC2) UnmarshalBinary(b []byte) error {
	var res FalconxC2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
