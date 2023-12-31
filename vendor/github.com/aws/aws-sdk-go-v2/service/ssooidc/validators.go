// Code generated by smithy-go-codegen DO NOT EDIT.

package ssooidc

import (
	"context"
	"fmt"
	smithy "github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
)

type validateOpCreateToken struct {
}

func (*validateOpCreateToken) ID() string {
	return "OperationInputValidation"
}

func (m *validateOpCreateToken) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	input, ok := in.Parameters.(*CreateTokenInput)
	if !ok {
		return out, metadata, fmt.Errorf("unknown input parameters type %T", in.Parameters)
	}
	if err := validateOpCreateTokenInput(input); err != nil {
		return out, metadata, err
	}
	return next.HandleInitialize(ctx, in)
}

type validateOpCreateTokenWithIAM struct {
}

func (*validateOpCreateTokenWithIAM) ID() string {
	return "OperationInputValidation"
}

func (m *validateOpCreateTokenWithIAM) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	input, ok := in.Parameters.(*CreateTokenWithIAMInput)
	if !ok {
		return out, metadata, fmt.Errorf("unknown input parameters type %T", in.Parameters)
	}
	if err := validateOpCreateTokenWithIAMInput(input); err != nil {
		return out, metadata, err
	}
	return next.HandleInitialize(ctx, in)
}

type validateOpRegisterClient struct {
}

func (*validateOpRegisterClient) ID() string {
	return "OperationInputValidation"
}

func (m *validateOpRegisterClient) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	input, ok := in.Parameters.(*RegisterClientInput)
	if !ok {
		return out, metadata, fmt.Errorf("unknown input parameters type %T", in.Parameters)
	}
	if err := validateOpRegisterClientInput(input); err != nil {
		return out, metadata, err
	}
	return next.HandleInitialize(ctx, in)
}

type validateOpStartDeviceAuthorization struct {
}

func (*validateOpStartDeviceAuthorization) ID() string {
	return "OperationInputValidation"
}

func (m *validateOpStartDeviceAuthorization) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	input, ok := in.Parameters.(*StartDeviceAuthorizationInput)
	if !ok {
		return out, metadata, fmt.Errorf("unknown input parameters type %T", in.Parameters)
	}
	if err := validateOpStartDeviceAuthorizationInput(input); err != nil {
		return out, metadata, err
	}
	return next.HandleInitialize(ctx, in)
}

func addOpCreateTokenValidationMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(&validateOpCreateToken{}, middleware.After)
}

func addOpCreateTokenWithIAMValidationMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(&validateOpCreateTokenWithIAM{}, middleware.After)
}

func addOpRegisterClientValidationMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(&validateOpRegisterClient{}, middleware.After)
}

func addOpStartDeviceAuthorizationValidationMiddleware(stack *middleware.Stack) error {
	return stack.Initialize.Add(&validateOpStartDeviceAuthorization{}, middleware.After)
}

func validateOpCreateTokenInput(v *CreateTokenInput) error {
	if v == nil {
		return nil
	}
	invalidParams := smithy.InvalidParamsError{Context: "CreateTokenInput"}
	if v.ClientId == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientId"))
	}
	if v.ClientSecret == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientSecret"))
	}
	if v.GrantType == nil {
		invalidParams.Add(smithy.NewErrParamRequired("GrantType"))
	}
	if invalidParams.Len() > 0 {
		return invalidParams
	} else {
		return nil
	}
}

func validateOpCreateTokenWithIAMInput(v *CreateTokenWithIAMInput) error {
	if v == nil {
		return nil
	}
	invalidParams := smithy.InvalidParamsError{Context: "CreateTokenWithIAMInput"}
	if v.ClientId == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientId"))
	}
	if v.GrantType == nil {
		invalidParams.Add(smithy.NewErrParamRequired("GrantType"))
	}
	if invalidParams.Len() > 0 {
		return invalidParams
	} else {
		return nil
	}
}

func validateOpRegisterClientInput(v *RegisterClientInput) error {
	if v == nil {
		return nil
	}
	invalidParams := smithy.InvalidParamsError{Context: "RegisterClientInput"}
	if v.ClientName == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientName"))
	}
	if v.ClientType == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientType"))
	}
	if invalidParams.Len() > 0 {
		return invalidParams
	} else {
		return nil
	}
}

func validateOpStartDeviceAuthorizationInput(v *StartDeviceAuthorizationInput) error {
	if v == nil {
		return nil
	}
	invalidParams := smithy.InvalidParamsError{Context: "StartDeviceAuthorizationInput"}
	if v.ClientId == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientId"))
	}
	if v.ClientSecret == nil {
		invalidParams.Add(smithy.NewErrParamRequired("ClientSecret"))
	}
	if v.StartUrl == nil {
		invalidParams.Add(smithy.NewErrParamRequired("StartUrl"))
	}
	if invalidParams.Len() > 0 {
		return invalidParams
	} else {
		return nil
	}
}
