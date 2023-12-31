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

// StateOnlineStateResultV1 state online state result v1
//
// swagger:model state.OnlineStateResultV1
type StateOnlineStateResultV1 struct {

	// cid
	Cid string `json:"cid,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

	// last seen
	// Format: date-time
	LastSeen strfmt.DateTime `json:"last_seen,omitempty"`

	// state
	// Required: true
	State *string `json:"state"`
}

// Validate validates this state online state result v1
func (m *StateOnlineStateResultV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastSeen(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateState(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *StateOnlineStateResultV1) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *StateOnlineStateResultV1) validateLastSeen(formats strfmt.Registry) error {
	if swag.IsZero(m.LastSeen) { // not required
		return nil
	}

	if err := validate.FormatOf("last_seen", "body", "date-time", m.LastSeen.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *StateOnlineStateResultV1) validateState(formats strfmt.Registry) error {

	if err := validate.Required("state", "body", m.State); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this state online state result v1 based on context it is used
func (m *StateOnlineStateResultV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *StateOnlineStateResultV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *StateOnlineStateResultV1) UnmarshalBinary(b []byte) error {
	var res StateOnlineStateResultV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
