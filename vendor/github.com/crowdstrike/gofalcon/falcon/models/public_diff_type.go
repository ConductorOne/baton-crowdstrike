// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PublicDiffType public diff type
//
// swagger:model public.DiffType
type PublicDiffType struct {

	// hash
	Hash *PublicDiffHash `json:"hash,omitempty"`
}

// Validate validates this public diff type
func (m *PublicDiffType) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHash(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicDiffType) validateHash(formats strfmt.Registry) error {
	if swag.IsZero(m.Hash) { // not required
		return nil
	}

	if m.Hash != nil {
		if err := m.Hash.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("hash")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this public diff type based on the context it is used
func (m *PublicDiffType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateHash(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicDiffType) contextValidateHash(ctx context.Context, formats strfmt.Registry) error {

	if m.Hash != nil {

		if swag.IsZero(m.Hash) { // not required
			return nil
		}

		if err := m.Hash.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("hash")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("hash")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PublicDiffType) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PublicDiffType) UnmarshalBinary(b []byte) error {
	var res PublicDiffType
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
