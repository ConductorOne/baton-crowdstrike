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

// ScheduledexclusionsUpdateRequest scheduledexclusions update request
//
// swagger:model scheduledexclusions.UpdateRequest
type ScheduledexclusionsUpdateRequest struct {

	// description
	Description string `json:"description,omitempty"`

	// id
	// Required: true
	ID *string `json:"id"`

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

// Validate validates this scheduledexclusions update request
func (m *ScheduledexclusionsUpdateRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

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

func (m *ScheduledexclusionsUpdateRequest) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *ScheduledexclusionsUpdateRequest) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ScheduledexclusionsUpdateRequest) validateRepeated(formats strfmt.Registry) error {
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

func (m *ScheduledexclusionsUpdateRequest) validateTimezone(formats strfmt.Registry) error {

	if err := validate.Required("timezone", "body", m.Timezone); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this scheduledexclusions update request based on the context it is used
func (m *ScheduledexclusionsUpdateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRepeated(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScheduledexclusionsUpdateRequest) contextValidateRepeated(ctx context.Context, formats strfmt.Registry) error {

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
func (m *ScheduledexclusionsUpdateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScheduledexclusionsUpdateRequest) UnmarshalBinary(b []byte) error {
	var res ScheduledexclusionsUpdateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}