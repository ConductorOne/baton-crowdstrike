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

// ModelsExclusionConditionRequest models exclusion condition request
//
// swagger:model models.ExclusionConditionRequest
type ModelsExclusionConditionRequest struct {

	// description
	Description string `json:"description,omitempty"`

	// prop
	// Required: true
	Prop *string `json:"prop"`

	// ttl
	TTL float64 `json:"ttl,omitempty"`

	// value
	// Required: true
	Value []string `json:"value"`
}

// Validate validates this models exclusion condition request
func (m *ModelsExclusionConditionRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateProp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsExclusionConditionRequest) validateProp(formats strfmt.Registry) error {

	if err := validate.Required("prop", "body", m.Prop); err != nil {
		return err
	}

	return nil
}

func (m *ModelsExclusionConditionRequest) validateValue(formats strfmt.Registry) error {

	if err := validate.Required("value", "body", m.Value); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models exclusion condition request based on context it is used
func (m *ModelsExclusionConditionRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsExclusionConditionRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsExclusionConditionRequest) UnmarshalBinary(b []byte) error {
	var res ModelsExclusionConditionRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}