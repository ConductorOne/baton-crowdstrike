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

// DomainScanScheduleDataV1 domain scan schedule data v1
//
// swagger:model domain.ScanScheduleDataV1
type DomainScanScheduleDataV1 struct {

	// cloud platform
	// Required: true
	CloudPlatform *string `json:"cloud_platform"`

	// next scan timestamp
	// Format: date-time
	NextScanTimestamp strfmt.DateTime `json:"next_scan_timestamp,omitempty"`

	// scan interval
	ScanInterval string `json:"scan_interval,omitempty"`

	// scan schedule
	ScanSchedule string `json:"scan_schedule,omitempty"`
}

// Validate validates this domain scan schedule data v1
func (m *DomainScanScheduleDataV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCloudPlatform(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNextScanTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainScanScheduleDataV1) validateCloudPlatform(formats strfmt.Registry) error {

	if err := validate.Required("cloud_platform", "body", m.CloudPlatform); err != nil {
		return err
	}

	return nil
}

func (m *DomainScanScheduleDataV1) validateNextScanTimestamp(formats strfmt.Registry) error {
	if swag.IsZero(m.NextScanTimestamp) { // not required
		return nil
	}

	if err := validate.FormatOf("next_scan_timestamp", "body", "date-time", m.NextScanTimestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain scan schedule data v1 based on context it is used
func (m *DomainScanScheduleDataV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainScanScheduleDataV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainScanScheduleDataV1) UnmarshalBinary(b []byte) error {
	var res DomainScanScheduleDataV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
