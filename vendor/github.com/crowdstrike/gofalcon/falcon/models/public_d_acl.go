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
)

// PublicDACL public d ACL
//
// swagger:model public.DACL
type PublicDACL struct {

	// Possible values: 0 - MODIFIED, 1 - NULL, 2 - EMPTY, 3 - SAME
	ChangesType int32 `json:"changes_type,omitempty"`

	// entity list
	EntityList []*PublicDACLEntity `json:"entity_list"`
}

// Validate validates this public d ACL
func (m *PublicDACL) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEntityList(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicDACL) validateEntityList(formats strfmt.Registry) error {
	if swag.IsZero(m.EntityList) { // not required
		return nil
	}

	for i := 0; i < len(m.EntityList); i++ {
		if swag.IsZero(m.EntityList[i]) { // not required
			continue
		}

		if m.EntityList[i] != nil {
			if err := m.EntityList[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("entity_list" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("entity_list" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this public d ACL based on the context it is used
func (m *PublicDACL) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEntityList(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PublicDACL) contextValidateEntityList(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.EntityList); i++ {

		if m.EntityList[i] != nil {

			if swag.IsZero(m.EntityList[i]) { // not required
				return nil
			}

			if err := m.EntityList[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("entity_list" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("entity_list" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *PublicDACL) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PublicDACL) UnmarshalBinary(b []byte) error {
	var res PublicDACL
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
