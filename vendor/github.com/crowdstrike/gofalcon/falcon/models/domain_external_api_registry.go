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

// DomainExternalAPIRegistry domain external API registry
//
// swagger:model domain.ExternalAPIRegistry
type DomainExternalAPIRegistry struct {

	// created at
	// Required: true
	CreatedAt *string `json:"created_at"`

	// credential
	Credential *DomainExternalCredentialResponse `json:"credential,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

	// last refreshed at
	// Required: true
	LastRefreshedAt *string `json:"last_refreshed_at"`

	// next refresh at
	// Required: true
	NextRefreshAt *string `json:"next_refresh_at"`

	// refresh interval
	// Required: true
	RefreshInterval *int32 `json:"refresh_interval"`

	// state
	// Required: true
	State *string `json:"state"`

	// state changed at
	// Required: true
	StateChangedAt *string `json:"state_changed_at"`

	// type
	// Required: true
	Type *string `json:"type"`

	// updated at
	// Required: true
	UpdatedAt *string `json:"updated_at"`

	// url
	// Required: true
	URL *string `json:"url"`

	// url uniqueness alias
	// Required: true
	URLUniquenessAlias *string `json:"url_uniqueness_alias"`

	// user defined alias
	// Required: true
	UserDefinedAlias *string `json:"user_defined_alias"`
}

// Validate validates this domain external API registry
func (m *DomainExternalAPIRegistry) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCredential(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastRefreshedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextRefreshAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRefreshInterval(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStateChangedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateURL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateURLUniquenessAlias(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserDefinedAlias(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAPIRegistry) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("created_at", "body", m.CreatedAt); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateCredential(formats strfmt.Registry) error {
	if swag.IsZero(m.Credential) { // not required
		return nil
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

func (m *DomainExternalAPIRegistry) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateLastRefreshedAt(formats strfmt.Registry) error {

	if err := validate.Required("last_refreshed_at", "body", m.LastRefreshedAt); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateNextRefreshAt(formats strfmt.Registry) error {

	if err := validate.Required("next_refresh_at", "body", m.NextRefreshAt); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateRefreshInterval(formats strfmt.Registry) error {

	if err := validate.Required("refresh_interval", "body", m.RefreshInterval); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateState(formats strfmt.Registry) error {

	if err := validate.Required("state", "body", m.State); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateStateChangedAt(formats strfmt.Registry) error {

	if err := validate.Required("state_changed_at", "body", m.StateChangedAt); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updated_at", "body", m.UpdatedAt); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateURL(formats strfmt.Registry) error {

	if err := validate.Required("url", "body", m.URL); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateURLUniquenessAlias(formats strfmt.Registry) error {

	if err := validate.Required("url_uniqueness_alias", "body", m.URLUniquenessAlias); err != nil {
		return err
	}

	return nil
}

func (m *DomainExternalAPIRegistry) validateUserDefinedAlias(formats strfmt.Registry) error {

	if err := validate.Required("user_defined_alias", "body", m.UserDefinedAlias); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this domain external API registry based on the context it is used
func (m *DomainExternalAPIRegistry) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCredential(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainExternalAPIRegistry) contextValidateCredential(ctx context.Context, formats strfmt.Registry) error {

	if m.Credential != nil {

		if swag.IsZero(m.Credential) { // not required
			return nil
		}

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
func (m *DomainExternalAPIRegistry) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainExternalAPIRegistry) UnmarshalBinary(b []byte) error {
	var res DomainExternalAPIRegistry
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}