// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// RequestsDeviceControlPolicySettingsV1 requests device control policy settings v1
//
// swagger:model requests.DeviceControlPolicySettingsV1
type RequestsDeviceControlPolicySettingsV1 struct {

	// Settings that apply to a USB Class
	// Required: true
	Classes []*RequestsDeviceControlPolicyClassSettingsV1 `json:"classes"`

	// An array of exception IDs to delete from the policy
	// Required: true
	DeleteExceptions []string `json:"delete_exceptions"`

	// Does the end user receives a notification when the policy is violated
	// Required: true
	// Enum: [SILENT NOTIFY_USER]
	EndUserNotification *string `json:"end_user_notification"`

	// How is this policy enforced
	// Required: true
	// Enum: [MONITOR_ONLY MONITOR_ENFORCE]
	EnforcementMode *string `json:"enforcement_mode"`
}

// Validate validates this requests device control policy settings v1
func (m *RequestsDeviceControlPolicySettingsV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClasses(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeleteExceptions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndUserNotification(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnforcementMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestsDeviceControlPolicySettingsV1) validateClasses(formats strfmt.Registry) error {

	if err := validate.Required("classes", "body", m.Classes); err != nil {
		return err
	}

	for i := 0; i < len(m.Classes); i++ {
		if swag.IsZero(m.Classes[i]) { // not required
			continue
		}

		if m.Classes[i] != nil {
			if err := m.Classes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("classes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("classes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RequestsDeviceControlPolicySettingsV1) validateDeleteExceptions(formats strfmt.Registry) error {

	if err := validate.Required("delete_exceptions", "body", m.DeleteExceptions); err != nil {
		return err
	}

	return nil
}

var requestsDeviceControlPolicySettingsV1TypeEndUserNotificationPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["SILENT","NOTIFY_USER"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		requestsDeviceControlPolicySettingsV1TypeEndUserNotificationPropEnum = append(requestsDeviceControlPolicySettingsV1TypeEndUserNotificationPropEnum, v)
	}
}

const (

	// RequestsDeviceControlPolicySettingsV1EndUserNotificationSILENT captures enum value "SILENT"
	RequestsDeviceControlPolicySettingsV1EndUserNotificationSILENT string = "SILENT"

	// RequestsDeviceControlPolicySettingsV1EndUserNotificationNOTIFYUSER captures enum value "NOTIFY_USER"
	RequestsDeviceControlPolicySettingsV1EndUserNotificationNOTIFYUSER string = "NOTIFY_USER"
)

// prop value enum
func (m *RequestsDeviceControlPolicySettingsV1) validateEndUserNotificationEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, requestsDeviceControlPolicySettingsV1TypeEndUserNotificationPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *RequestsDeviceControlPolicySettingsV1) validateEndUserNotification(formats strfmt.Registry) error {

	if err := validate.Required("end_user_notification", "body", m.EndUserNotification); err != nil {
		return err
	}

	// value enum
	if err := m.validateEndUserNotificationEnum("end_user_notification", "body", *m.EndUserNotification); err != nil {
		return err
	}

	return nil
}

var requestsDeviceControlPolicySettingsV1TypeEnforcementModePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["MONITOR_ONLY","MONITOR_ENFORCE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		requestsDeviceControlPolicySettingsV1TypeEnforcementModePropEnum = append(requestsDeviceControlPolicySettingsV1TypeEnforcementModePropEnum, v)
	}
}

const (

	// RequestsDeviceControlPolicySettingsV1EnforcementModeMONITORONLY captures enum value "MONITOR_ONLY"
	RequestsDeviceControlPolicySettingsV1EnforcementModeMONITORONLY string = "MONITOR_ONLY"

	// RequestsDeviceControlPolicySettingsV1EnforcementModeMONITORENFORCE captures enum value "MONITOR_ENFORCE"
	RequestsDeviceControlPolicySettingsV1EnforcementModeMONITORENFORCE string = "MONITOR_ENFORCE"
)

// prop value enum
func (m *RequestsDeviceControlPolicySettingsV1) validateEnforcementModeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, requestsDeviceControlPolicySettingsV1TypeEnforcementModePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *RequestsDeviceControlPolicySettingsV1) validateEnforcementMode(formats strfmt.Registry) error {

	if err := validate.Required("enforcement_mode", "body", m.EnforcementMode); err != nil {
		return err
	}

	// value enum
	if err := m.validateEnforcementModeEnum("enforcement_mode", "body", *m.EnforcementMode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this requests device control policy settings v1 based on the context it is used
func (m *RequestsDeviceControlPolicySettingsV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClasses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestsDeviceControlPolicySettingsV1) contextValidateClasses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Classes); i++ {

		if m.Classes[i] != nil {
			if err := m.Classes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("classes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("classes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestsDeviceControlPolicySettingsV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestsDeviceControlPolicySettingsV1) UnmarshalBinary(b []byte) error {
	var res RequestsDeviceControlPolicySettingsV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}