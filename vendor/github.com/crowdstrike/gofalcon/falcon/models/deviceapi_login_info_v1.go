// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DeviceapiLoginInfoV1 deviceapi login info v1
//
// swagger:model deviceapi.LoginInfoV1
type DeviceapiLoginInfoV1 struct {

	// login time
	LoginTime string `json:"login_time,omitempty"`

	// user name
	UserName string `json:"user_name,omitempty"`
}

// Validate validates this deviceapi login info v1
func (m *DeviceapiLoginInfoV1) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this deviceapi login info v1 based on context it is used
func (m *DeviceapiLoginInfoV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeviceapiLoginInfoV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeviceapiLoginInfoV1) UnmarshalBinary(b []byte) error {
	var res DeviceapiLoginInfoV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
