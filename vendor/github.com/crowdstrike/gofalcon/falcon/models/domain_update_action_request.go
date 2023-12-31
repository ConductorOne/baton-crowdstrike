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

// DomainUpdateActionRequest domain update action request
//
// swagger:model domain.UpdateActionRequest
type DomainUpdateActionRequest struct {

	// content format
	// Required: true
	ContentFormat *string `json:"content_format"`

	// frequency
	// Required: true
	Frequency *string `json:"frequency"`

	// id
	// Required: true
	ID *string `json:"id"`

	// recipients
	// Required: true
	Recipients []string `json:"recipients"`

	// status
	// Required: true
	Status *string `json:"status"`

	// trigger matchless
	// Required: true
	TriggerMatchless *bool `json:"trigger_matchless"`
}

// Validate validates this domain update action request
func (m *DomainUpdateActionRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContentFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFrequency(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecipients(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTriggerMatchless(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainUpdateActionRequest) validateContentFormat(formats strfmt.Registry) error {

	if err := validate.Required("content_format", "body", m.ContentFormat); err != nil {
		return err
	}

	return nil
}

func (m *DomainUpdateActionRequest) validateFrequency(formats strfmt.Registry) error {

	if err := validate.Required("frequency", "body", m.Frequency); err != nil {
		return err
	}

	return nil
}

func (m *DomainUpdateActionRequest) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *DomainUpdateActionRequest) validateRecipients(formats strfmt.Registry) error {

	if err := validate.Required("recipients", "body", m.Recipients); err != nil {
		return err
	}

	return nil
}

func (m *DomainUpdateActionRequest) validateStatus(formats strfmt.Registry) error {

	if err := validate.Required("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

func (m *DomainUpdateActionRequest) validateTriggerMatchless(formats strfmt.Registry) error {

	if err := validate.Required("trigger_matchless", "body", m.TriggerMatchless); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain update action request based on context it is used
func (m *DomainUpdateActionRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainUpdateActionRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainUpdateActionRequest) UnmarshalBinary(b []byte) error {
	var res DomainUpdateActionRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
