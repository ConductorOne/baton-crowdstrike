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

// PublicPolicyRuleGroup public policy rule group
//
// swagger:model public.PolicyRuleGroup
type PublicPolicyRuleGroup struct {

	// name
	Name string `json:"name,omitempty"`

	// rule
	Rule *PublicPolicyRule `json:"rule,omitempty"`
}

// Validate validates this public policy rule group
func (m *PublicPolicyRuleGroup) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRule(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicPolicyRuleGroup) validateRule(formats strfmt.Registry) error {
	if swag.IsZero(m.Rule) { // not required
		return nil
	}

	if m.Rule != nil {
		if err := m.Rule.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rule")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rule")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this public policy rule group based on the context it is used
func (m *PublicPolicyRuleGroup) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRule(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicPolicyRuleGroup) contextValidateRule(ctx context.Context, formats strfmt.Registry) error {

	if m.Rule != nil {

		if swag.IsZero(m.Rule) { // not required
			return nil
		}

		if err := m.Rule.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rule")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rule")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PublicPolicyRuleGroup) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PublicPolicyRuleGroup) UnmarshalBinary(b []byte) error {
	var res PublicPolicyRuleGroup
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
