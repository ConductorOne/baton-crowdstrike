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

// DomainMultiCommandExecuteResponse domain multi command execute response
//
// swagger:model domain.MultiCommandExecuteResponse
type DomainMultiCommandExecuteResponse struct {

	// resources
	// Required: true
	Resources map[string]DomainMultiStatusSensorResponse `json:"resources"`
}

// Validate validates this domain multi command execute response
func (m *DomainMultiCommandExecuteResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateResources(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainMultiCommandExecuteResponse) validateResources(formats strfmt.Registry) error {

	if err := validate.Required("resources", "body", m.Resources); err != nil {
		return err
	}

	for k := range m.Resources {

		if err := validate.Required("resources"+"."+k, "body", m.Resources[k]); err != nil {
			return err
		}
		if val, ok := m.Resources[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("resources" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("resources" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this domain multi command execute response based on the context it is used
func (m *DomainMultiCommandExecuteResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateResources(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainMultiCommandExecuteResponse) contextValidateResources(ctx context.Context, formats strfmt.Registry) error {

	if err := validate.Required("resources", "body", m.Resources); err != nil {
		return err
	}

	for k := range m.Resources {

		if val, ok := m.Resources[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainMultiCommandExecuteResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainMultiCommandExecuteResponse) UnmarshalBinary(b []byte) error {
	var res DomainMultiCommandExecuteResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
