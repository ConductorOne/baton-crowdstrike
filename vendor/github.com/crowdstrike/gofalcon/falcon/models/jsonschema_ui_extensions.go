// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// JsonschemaUIExtensions jsonschema UI extensions
//
// swagger:model jsonschema.UIExtensions
type JsonschemaUIExtensions struct {

	// helper text
	HelperText string `json:"helperText,omitempty"`
}

// Validate validates this jsonschema UI extensions
func (m *JsonschemaUIExtensions) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this jsonschema UI extensions based on context it is used
func (m *JsonschemaUIExtensions) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *JsonschemaUIExtensions) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JsonschemaUIExtensions) UnmarshalBinary(b []byte) error {
	var res JsonschemaUIExtensions
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
