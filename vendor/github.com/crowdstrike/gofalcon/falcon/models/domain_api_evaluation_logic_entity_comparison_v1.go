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

// DomainAPIEvaluationLogicEntityComparisonV1 domain API evaluation logic entity comparison v1
//
// swagger:model domain.APIEvaluationLogicEntityComparisonV1
type DomainAPIEvaluationLogicEntityComparisonV1 struct {

	// actual value field
	// Required: true
	ActualValueField *string `json:"actual_value_field"`

	// expected value
	// Required: true
	ExpectedValue DomainAPIEvaluationLogicEntityComparisonV1ExpectedValue `json:"expected_value"`

	// operation
	// Required: true
	Operation *string `json:"operation"`

	// value datatype
	// Required: true
	ValueDatatype *string `json:"value_datatype"`
}

// Validate validates this domain API evaluation logic entity comparison v1
func (m *DomainAPIEvaluationLogicEntityComparisonV1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActualValueField(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpectedValue(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOperation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValueDatatype(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DomainAPIEvaluationLogicEntityComparisonV1) validateActualValueField(formats strfmt.Registry) error {

	if err := validate.Required("actual_value_field", "body", m.ActualValueField); err != nil {
		return err
	}

	return nil
}

func (m *DomainAPIEvaluationLogicEntityComparisonV1) validateExpectedValue(formats strfmt.Registry) error {

	if m.ExpectedValue == nil {
		return errors.Required("expected_value", "body", nil)
	}

	return nil
}

func (m *DomainAPIEvaluationLogicEntityComparisonV1) validateOperation(formats strfmt.Registry) error {

	if err := validate.Required("operation", "body", m.Operation); err != nil {
		return err
	}

	return nil
}

func (m *DomainAPIEvaluationLogicEntityComparisonV1) validateValueDatatype(formats strfmt.Registry) error {

	if err := validate.Required("value_datatype", "body", m.ValueDatatype); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this domain API evaluation logic entity comparison v1 based on context it is used
func (m *DomainAPIEvaluationLogicEntityComparisonV1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DomainAPIEvaluationLogicEntityComparisonV1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DomainAPIEvaluationLogicEntityComparisonV1) UnmarshalBinary(b []byte) error {
	var res DomainAPIEvaluationLogicEntityComparisonV1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
