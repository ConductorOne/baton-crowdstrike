// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DomainExternalAssetDiscoveryAttributes domain external asset discovery attributes
//
// swagger:model domain.ExternalAssetDiscoveryAttributes
type DomainExternalAssetDiscoveryAttributes struct {

	// Alternative discovery paths
	AlternativePaths []*DomainExternalAssetDiscoveryPathAttributes `json:"alternative_paths"`

	// The chosen discovery path
	// Required: true
	Path *DomainExternalAssetDiscoveryPathAttributes `json:"path"`
}

// Validate validates this domain external asset discovery attributes
func (m *DomainExternalAssetDiscoveryAttributes) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAlternativePaths(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePath(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAssetDiscoveryAttributes) validateAlternativePaths(formats strfmt.Registry) error {
	if swag.IsZero(m.AlternativePaths) { // not required
		return nil
	}

	for i := 0; i < len(m.AlternativePaths); i++ {
		if swag.IsZero(m.AlternativePaths[i]) { // not required
			continue
		}

		if m.AlternativePaths[i] != nil {
			if err := m.AlternativePaths[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("alternative_paths" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("alternative_paths" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainExternalAssetDiscoveryAttributes) validatePath(formats strfmt.Registry) error {

	if err := validate.Required("path", "body", m.Path); err != nil {
		return err
	}

	if m.Path != nil {
		if err := m.Path.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("path")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("path")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this domain external asset discovery attributes based on the context it is used
func (m *DomainExternalAssetDiscoveryAttributes) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAlternativePaths(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePath(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAssetDiscoveryAttributes) contextValidateAlternativePaths(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AlternativePaths); i++ {

		if m.AlternativePaths[i] != nil {

			if swag.IsZero(m.AlternativePaths[i]) { // not required
				return nil
			}

			if err := m.AlternativePaths[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("alternative_paths" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("alternative_paths" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DomainExternalAssetDiscoveryAttributes) contextValidatePath(ctx context.Context, formats strfmt.Registry) error {

	if m.Path != nil {

		if err := m.Path.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("path")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("path")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DomainExternalAssetDiscoveryAttributes) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainExternalAssetDiscoveryAttributes) UnmarshalBinary(b []byte) error {
	var res DomainExternalAssetDiscoveryAttributes
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}