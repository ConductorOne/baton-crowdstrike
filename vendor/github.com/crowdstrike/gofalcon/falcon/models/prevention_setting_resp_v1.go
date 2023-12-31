// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PreventionSettingRespV1 A prevention policy setting
//
// swagger:model prevention.SettingRespV1
type PreventionSettingRespV1 struct {

	// The human readable description of the setting
	Description string `json:"description,omitempty"`

	// The id of the setting
	// Required: true
	ID *string `json:"id"`

	// The name of the setting
	// Required: true
	Name *string `json:"name"`

	// The type of the setting which can be used as a hint when displaying in the UI
	// Required: true
	// Enum: [toggle mlslider]
	Type *string `json:"type"`

	// The value for the setting. For a toggle this value will take the form {'enabled':true|false}. For an mlslider this will take the form {'detection':'DISABLED|CAUTIOUS|MODERATE|AGGRESSIVE|EXTRA_AGGRESSIVE','prevention':'DISABLED|CAUTIOUS|MODERATE|AGGRESSIVE|EXTRA_AGGRESSIVE'}
	// Required: true
	Value interface{} `json:"value"`
}

// Validate validates this prevention setting resp v1
func (m *PreventionSettingRespV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
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

func (m *PreventionSettingRespV1) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *PreventionSettingRespV1) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

var preventionSettingRespV1TypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["toggle","mlslider"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		preventionSettingRespV1TypeTypePropEnum = append(preventionSettingRespV1TypeTypePropEnum, v)
	}
}

const (

	// PreventionSettingRespV1TypeToggle captures enum value "toggle"
	PreventionSettingRespV1TypeToggle string = "toggle"

	// PreventionSettingRespV1TypeMlslider captures enum value "mlslider"
	PreventionSettingRespV1TypeMlslider string = "mlslider"
)

// prop value enum
func (m *PreventionSettingRespV1) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, preventionSettingRespV1TypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *PreventionSettingRespV1) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", *m.Type); err != nil {
		return err
	}

	return nil
}

func (m *PreventionSettingRespV1) validateValue(formats strfmt.Registry) error {

	if m.Value == nil {
		return errors.Required("value", "body", nil)
	}

	return nil
}

// ContextValidate validates this prevention setting resp v1 based on context it is used
func (m *PreventionSettingRespV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PreventionSettingRespV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PreventionSettingRespV1) UnmarshalBinary(b []byte) error {
	var res PreventionSettingRespV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
