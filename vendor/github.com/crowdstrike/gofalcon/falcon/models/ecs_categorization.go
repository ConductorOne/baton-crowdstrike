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

// EcsCategorization ecs categorization
//
// swagger:model ecs.Categorization
type EcsCategorization struct {

	// categories
	// Required: true
	Categories []string `json:"Categories"`

	// kind
	// Required: true
	Kind *string `json:"Kind"`

	// outcome
	// Required: true
	Outcome *string `json:"Outcome"`

	// types
	// Required: true
	Types []string `json:"Types"`
}

// Validate validates this ecs categorization
func (m *EcsCategorization) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCategories(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKind(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOutcome(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTypes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EcsCategorization) validateCategories(formats strfmt.Registry) error {

	if err := validate.Required("Categories", "body", m.Categories); err != nil {
		return err
	}

	return nil
}

func (m *EcsCategorization) validateKind(formats strfmt.Registry) error {

	if err := validate.Required("Kind", "body", m.Kind); err != nil {
		return err
	}

	return nil
}

func (m *EcsCategorization) validateOutcome(formats strfmt.Registry) error {

	if err := validate.Required("Outcome", "body", m.Outcome); err != nil {
		return err
	}

	return nil
}

func (m *EcsCategorization) validateTypes(formats strfmt.Registry) error {

	if err := validate.Required("Types", "body", m.Types); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this ecs categorization based on context it is used
func (m *EcsCategorization) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EcsCategorization) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EcsCategorization) UnmarshalBinary(b []byte) error {
	var res EcsCategorization
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
