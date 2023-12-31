// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PolicySensorUpdateScheduler policy sensor update scheduler
//
// swagger:model policy.SensorUpdateScheduler
type PolicySensorUpdateScheduler struct {

	// enabled
	// Required: true
	Enabled *bool `json:"enabled"`

	// schedules
	// Required: true
	Schedules []*PolicySensorUpdateSchedule `json:"schedules"`

	// timezone
	// Required: true
	Timezone *string `json:"timezone"`
}

// Validate validates this policy sensor update scheduler
func (m *PolicySensorUpdateScheduler) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSchedules(formats); err != nil {
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

func (m *PolicySensorUpdateScheduler) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", m.Enabled); err != nil {
		return err
	}

	return nil
}

func (m *PolicySensorUpdateScheduler) validateSchedules(formats strfmt.Registry) error {

	if err := validate.Required("schedules", "body", m.Schedules); err != nil {
		return err
	}

	for i := 0; i < len(m.Schedules); i++ {
		if swag.IsZero(m.Schedules[i]) { // not required
			continue
		}

		if m.Schedules[i] != nil {
			if err := m.Schedules[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("schedules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("schedules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PolicySensorUpdateScheduler) validateTimezone(formats strfmt.Registry) error {

	if err := validate.Required("timezone", "body", m.Timezone); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this policy sensor update scheduler based on the context it is used
func (m *PolicySensorUpdateScheduler) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSchedules(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PolicySensorUpdateScheduler) contextValidateSchedules(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Schedules); i++ {

		if m.Schedules[i] != nil {

			if swag.IsZero(m.Schedules[i]) { // not required
				return nil
			}

			if err := m.Schedules[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("schedules" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("schedules" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *PolicySensorUpdateScheduler) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PolicySensorUpdateScheduler) UnmarshalBinary(b []byte) error {
	var res PolicySensorUpdateScheduler
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
