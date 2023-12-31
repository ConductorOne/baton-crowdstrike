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

// DomainPastebinTextSource domain pastebin text source
//
// swagger:model domain.PastebinTextSource
type DomainPastebinTextSource struct {

	// The name of the author
	// Required: true
	AuthorName *string `json:"author_name"`

	// legacy source
	LegacySource DomainPastebinTextSourceLegacySource `json:"legacy_source,omitempty"`

	// Unique ID of the Pastebin content
	// Required: true
	PastebinID *string `json:"pastebin_id"`

	// The Pastebin URL
	// Required: true
	SourceLink *string `json:"source_link"`

	// The title of the Pastebin content
	// Required: true
	Title *string `json:"title"`
}

// Validate validates this domain pastebin text source
func (m *DomainPastebinTextSource) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePastebinID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSourceLink(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTitle(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainPastebinTextSource) validateAuthorName(formats strfmt.Registry) error {

	if err := validate.Required("author_name", "body", m.AuthorName); err != nil {
		return err
	}

	return nil
}

func (m *DomainPastebinTextSource) validatePastebinID(formats strfmt.Registry) error {

	if err := validate.Required("pastebin_id", "body", m.PastebinID); err != nil {
		return err
	}

	return nil
}

func (m *DomainPastebinTextSource) validateSourceLink(formats strfmt.Registry) error {

	if err := validate.Required("source_link", "body", m.SourceLink); err != nil {
		return err
	}

	return nil
}

func (m *DomainPastebinTextSource) validateTitle(formats strfmt.Registry) error {

	if err := validate.Required("title", "body", m.Title); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain pastebin text source based on context it is used
func (m *DomainPastebinTextSource) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainPastebinTextSource) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainPastebinTextSource) UnmarshalBinary(b []byte) error {
	var res DomainPastebinTextSource
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
