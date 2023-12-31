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

// FwmgrFirewallPolicyContainerV1 fwmgr firewall policy container v1
//
// swagger:model fwmgr.firewall.PolicyContainerV1
type FwmgrFirewallPolicyContainerV1 struct {

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created on
	CreatedOn string `json:"created_on,omitempty"`

	// default inbound
	// Required: true
	DefaultInbound *string `json:"default_inbound"`

	// default outbound
	// Required: true
	DefaultOutbound *string `json:"default_outbound"`

	// deleted
	Deleted bool `json:"deleted,omitempty"`

	// enforce
	// Required: true
	Enforce *bool `json:"enforce"`

	// is default policy
	IsDefaultPolicy bool `json:"is_default_policy,omitempty"`

	// local logging
	// Required: true
	LocalLogging *bool `json:"local_logging"`

	// modified by
	ModifiedBy string `json:"modified_by,omitempty"`

	// modified on
	ModifiedOn string `json:"modified_on,omitempty"`

	// platform id
	// Required: true
	PlatformID *string `json:"platform_id"`

	// policy id
	// Required: true
	PolicyID *string `json:"policy_id"`

	// rule group ids
	// Required: true
	RuleGroupIds []string `json:"rule_group_ids"`

	// test mode
	// Required: true
	TestMode *bool `json:"test_mode"`

	// tracking
	Tracking string `json:"tracking,omitempty"`
}

// Validate validates this fwmgr firewall policy container v1
func (m *FwmgrFirewallPolicyContainerV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDefaultInbound(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultOutbound(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnforce(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocalLogging(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePlatformID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRuleGroupIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTestMode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateDefaultInbound(formats strfmt.Registry) error {

	if err := validate.Required("default_inbound", "body", m.DefaultInbound); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateDefaultOutbound(formats strfmt.Registry) error {

	if err := validate.Required("default_outbound", "body", m.DefaultOutbound); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateEnforce(formats strfmt.Registry) error {

	if err := validate.Required("enforce", "body", m.Enforce); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateLocalLogging(formats strfmt.Registry) error {

	if err := validate.Required("local_logging", "body", m.LocalLogging); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validatePlatformID(formats strfmt.Registry) error {

	if err := validate.Required("platform_id", "body", m.PlatformID); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validatePolicyID(formats strfmt.Registry) error {

	if err := validate.Required("policy_id", "body", m.PolicyID); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateRuleGroupIds(formats strfmt.Registry) error {

	if err := validate.Required("rule_group_ids", "body", m.RuleGroupIds); err != nil {
		return err
	}

	return nil
}

func (m *FwmgrFirewallPolicyContainerV1) validateTestMode(formats strfmt.Registry) error {

	if err := validate.Required("test_mode", "body", m.TestMode); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this fwmgr firewall policy container v1 based on context it is used
func (m *FwmgrFirewallPolicyContainerV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *FwmgrFirewallPolicyContainerV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *FwmgrFirewallPolicyContainerV1) UnmarshalBinary(b []byte) error {
	var res FwmgrFirewallPolicyContainerV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
