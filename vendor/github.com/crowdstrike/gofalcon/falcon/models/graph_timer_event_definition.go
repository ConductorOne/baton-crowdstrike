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

// GraphTimerEventDefinition graph timer event definition
//
// swagger:model graph.TimerEventDefinition
type GraphTimerEventDefinition struct {

	// End date in mm-dd-yyyy format
	EndDate string `json:"end_date,omitempty"`

	// Flag indicating if concurrent execution of scheduled workflow should be skipped or not
	// Required: true
	SkipConcurrent *bool `json:"skip_concurrent"`

	// Start date in mm-dd-yyyy format
	StartDate string `json:"start_date,omitempty"`

	// A time cycle element specifies repeating intervals, and can be specified using using cron expressions.
	// Required: true
	TimeCycle *string `json:"time_cycle"`

	// Timezone label from IANA timezone database, for example, America/Los_Angeles
	// Required: true
	Tz *string `json:"tz"`
}

// Validate validates this graph timer event definition
func (m *GraphTimerEventDefinition) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSkipConcurrent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimeCycle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTz(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GraphTimerEventDefinition) validateSkipConcurrent(formats strfmt.Registry) error {

	if err := validate.Required("skip_concurrent", "body", m.SkipConcurrent); err != nil {
		return err
	}

	return nil
}

func (m *GraphTimerEventDefinition) validateTimeCycle(formats strfmt.Registry) error {

	if err := validate.Required("time_cycle", "body", m.TimeCycle); err != nil {
		return err
	}

	return nil
}

func (m *GraphTimerEventDefinition) validateTz(formats strfmt.Registry) error {

	if err := validate.Required("tz", "body", m.Tz); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this graph timer event definition based on context it is used
func (m *GraphTimerEventDefinition) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GraphTimerEventDefinition) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GraphTimerEventDefinition) UnmarshalBinary(b []byte) error {
	var res GraphTimerEventDefinition
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}