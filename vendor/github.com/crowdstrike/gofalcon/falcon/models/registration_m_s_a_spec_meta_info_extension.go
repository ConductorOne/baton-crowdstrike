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

// RegistrationMSASpecMetaInfoExtension registration m s a spec meta info extension
//
// swagger:model registration.MSASpecMetaInfoExtension
type RegistrationMSASpecMetaInfoExtension struct {

	// meta info
	// Required: true
	MetaInfo *MsaMetaInfo `json:"MetaInfo"`

	// pagination
	Pagination *RegistrationMSAPagingExtension `json:"pagination,omitempty"`
}

// Validate validates this registration m s a spec meta info extension
func (m *RegistrationMSASpecMetaInfoExtension) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateMetaInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePagination(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationMSASpecMetaInfoExtension) validateMetaInfo(formats strfmt.Registry) error {

	if err := validate.Required("MetaInfo", "body", m.MetaInfo); err != nil {
		return err
	}

	if m.MetaInfo != nil {
		if err := m.MetaInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("MetaInfo")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("MetaInfo")
			}
			return err
		}
	}

	return nil
}

func (m *RegistrationMSASpecMetaInfoExtension) validatePagination(formats strfmt.Registry) error {
	if swag.IsZero(m.Pagination) { // not required
		return nil
	}

	if m.Pagination != nil {
		if err := m.Pagination.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this registration m s a spec meta info extension based on the context it is used
func (m *RegistrationMSASpecMetaInfoExtension) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetaInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePagination(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RegistrationMSASpecMetaInfoExtension) contextValidateMetaInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.MetaInfo != nil {

		if err := m.MetaInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("MetaInfo")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("MetaInfo")
			}
			return err
		}
	}

	return nil
}

func (m *RegistrationMSASpecMetaInfoExtension) contextValidatePagination(ctx context.Context, formats strfmt.Registry) error {

	if m.Pagination != nil {

		if swag.IsZero(m.Pagination) { // not required
			return nil
		}

		if err := m.Pagination.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pagination")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pagination")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RegistrationMSASpecMetaInfoExtension) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegistrationMSASpecMetaInfoExtension) UnmarshalBinary(b []byte) error {
	var res RegistrationMSASpecMetaInfoExtension
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
