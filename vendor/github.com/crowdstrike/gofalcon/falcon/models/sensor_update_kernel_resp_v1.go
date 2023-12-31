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

// SensorUpdateKernelRespV1 sensor update kernel resp v1
//
// swagger:model sensor_update.KernelRespV1
type SensorUpdateKernelRespV1 struct {

	// architecture
	// Required: true
	Architecture *string `json:"architecture"`

	// base package supported sensor versions
	// Required: true
	BasePackageSupportedSensorVersions []string `json:"base_package_supported_sensor_versions"`

	// created timestamp
	// Required: true
	CreatedTimestamp *string `json:"created_timestamp"`

	// distro
	// Required: true
	Distro *string `json:"distro"`

	// distro version
	// Required: true
	DistroVersion *string `json:"distro_version"`

	// flavor
	// Required: true
	Flavor *string `json:"flavor"`

	// id
	// Required: true
	ID *string `json:"id"`

	// modified timestamp
	// Required: true
	ModifiedTimestamp *string `json:"modified_timestamp"`

	// release
	// Required: true
	Release *string `json:"release"`

	// vendor
	// Required: true
	Vendor *string `json:"vendor"`

	// version
	// Required: true
	Version *string `json:"version"`

	// ztl module supported sensor versions
	// Required: true
	ZtlModuleSupportedSensorVersions []string `json:"ztl_module_supported_sensor_versions"`

	// ztl supported sensor versions
	// Required: true
	ZtlSupportedSensorVersions []string `json:"ztl_supported_sensor_versions"`
}

// Validate validates this sensor update kernel resp v1
func (m *SensorUpdateKernelRespV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateArchitecture(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBasePackageSupportedSensorVersions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDistro(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDistroVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFlavor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateModifiedTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRelease(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVendor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersion(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateZtlModuleSupportedSensorVersions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateZtlSupportedSensorVersions(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SensorUpdateKernelRespV1) validateArchitecture(formats strfmt.Registry) error {

	if err := validate.Required("architecture", "body", m.Architecture); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateBasePackageSupportedSensorVersions(formats strfmt.Registry) error {

	if err := validate.Required("base_package_supported_sensor_versions", "body", m.BasePackageSupportedSensorVersions); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateCreatedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("created_timestamp", "body", m.CreatedTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateDistro(formats strfmt.Registry) error {

	if err := validate.Required("distro", "body", m.Distro); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateDistroVersion(formats strfmt.Registry) error {

	if err := validate.Required("distro_version", "body", m.DistroVersion); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateFlavor(formats strfmt.Registry) error {

	if err := validate.Required("flavor", "body", m.Flavor); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateID(formats strfmt.Registry) error {

	if err := validate.Required("id", "body", m.ID); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateModifiedTimestamp(formats strfmt.Registry) error {

	if err := validate.Required("modified_timestamp", "body", m.ModifiedTimestamp); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateRelease(formats strfmt.Registry) error {

	if err := validate.Required("release", "body", m.Release); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateVendor(formats strfmt.Registry) error {

	if err := validate.Required("vendor", "body", m.Vendor); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateVersion(formats strfmt.Registry) error {

	if err := validate.Required("version", "body", m.Version); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateZtlModuleSupportedSensorVersions(formats strfmt.Registry) error {

	if err := validate.Required("ztl_module_supported_sensor_versions", "body", m.ZtlModuleSupportedSensorVersions); err != nil {
		return err
	}

	return nil
}

func (m *SensorUpdateKernelRespV1) validateZtlSupportedSensorVersions(formats strfmt.Registry) error {

	if err := validate.Required("ztl_supported_sensor_versions", "body", m.ZtlSupportedSensorVersions); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this sensor update kernel resp v1 based on context it is used
func (m *SensorUpdateKernelRespV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SensorUpdateKernelRespV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SensorUpdateKernelRespV1) UnmarshalBinary(b []byte) error {
	var res SensorUpdateKernelRespV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
