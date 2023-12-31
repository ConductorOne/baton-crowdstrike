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

// RegistryassessmentExternalRegistryPatchPayload registryassessment external registry patch payload
//
// swagger:model registryassessment.externalRegistryPatchPayload
type RegistryassessmentExternalRegistryPatchPayload struct {

	// credential
	// Required: true
	Credential *APICredPayload `json:"credential"`

	// state
	State string `json:"state,omitempty"`

	// user defined alias
	UserDefinedAlias string `json:"user_defined_alias,omitempty"`
}

// Validate validates this registryassessment external registry patch payload
func (m *RegistryassessmentExternalRegistryPatchPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCredential(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistryassessmentExternalRegistryPatchPayload) validateCredential(formats strfmt.Registry) error {

	if err := validate.Required("credential", "body", m.Credential); err != nil {
		return err
	}

	if m.Credential != nil {
		if err := m.Credential.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("credential")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("credential")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this registryassessment external registry patch payload based on the context it is used
func (m *RegistryassessmentExternalRegistryPatchPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCredential(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistryassessmentExternalRegistryPatchPayload) contextValidateCredential(ctx context.Context, formats strfmt.Registry) error {

	if m.Credential != nil {

		if err := m.Credential.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("credential")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("credential")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RegistryassessmentExternalRegistryPatchPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistryassessmentExternalRegistryPatchPayload) UnmarshalBinary(b []byte) error {
	var res RegistryassessmentExternalRegistryPatchPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
