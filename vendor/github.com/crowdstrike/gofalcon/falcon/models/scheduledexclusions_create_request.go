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

// ScheduledexclusionsCreateRequest scheduledexclusions create request
//
// swagger:model scheduledexclusions.CreateRequest
type ScheduledexclusionsCreateRequest struct {

	// description
	Description string `json:"description,omitempty"`

	// name
	// Required: true
	Name *string `json:"name"`

	// policy id
	PolicyID string `json:"policy_id,omitempty"`

	// processes
	Processes string `json:"processes,omitempty"`

	// repeated
	Repeated *ScheduledexclusionsRepeated `json:"repeated,omitempty"`

	// schedule end
	ScheduleEnd string `json:"schedule_end,omitempty"`

	// schedule start
	ScheduleStart string `json:"schedule_start,omitempty"`

	// timezone
	// Required: true
	Timezone *string `json:"timezone"`

	// users
	Users string `json:"users,omitempty"`
}

// Validate validates this scheduledexclusions create request
func (m *ScheduledexclusionsCreateRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRepeated(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimezone(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScheduledexclusionsCreateRequest) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ScheduledexclusionsCreateRequest) validateRepeated(formats strfmt.Registry) error {
	if swag.IsZero(m.Repeated) { // not required
		return nil
	}

	if m.Repeated != nil {
		if err := m.Repeated.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("repeated")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("repeated")
			}
			return err
		}
	}

	return nil
}

func (m *ScheduledexclusionsCreateRequest) validateTimezone(formats strfmt.Registry) error {

	if err := validate.Required("timezone", "body", m.Timezone); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this scheduledexclusions create request based on the context it is used
func (m *ScheduledexclusionsCreateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRepeated(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScheduledexclusionsCreateRequest) contextValidateRepeated(ctx context.Context, formats strfmt.Registry) error {

	if m.Repeated != nil {

		if swag.IsZero(m.Repeated) { // not required
			return nil
		}

		if err := m.Repeated.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("repeated")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("repeated")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ScheduledexclusionsCreateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScheduledexclusionsCreateRequest) UnmarshalBinary(b []byte) error {
	var res ScheduledexclusionsCreateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}