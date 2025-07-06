package validation

import (
	"testing"

	"gitlab.com/bcstudio1/tools/go-auth/validation"
)

func Test_Validation_Password_TableDriven(t *testing.T) {
	tests := []struct {
		testName          string
		expectSuccess     bool
		password          string
		minLength         int
		unauthorizedWords []string
	}{
		{
			testName:      "Success",
			expectSuccess: true,
			password:      "Er0utibl@nc",
		},
		{
			testName:      "Fail: Cannot set min length lower than 8",
			expectSuccess: false,
			password:      "8TCYZ@i", // length of 7. It should fail, because the default length of 8 should be used
			minLength:     3,
		},
		{
			testName:      "Fail: Too short after length increased",
			expectSuccess: false,
			password:      "SHU4@^pIeJ%k3V3^TV8B", // length of 20
			minLength:     23,
		},
		{
			testName:      "Fail: No uppercase",
			expectSuccess: false,
			password:      "n0upper_cases",
		},
		{
			testName:      "Fail: No lowercase",
			expectSuccess: false,
			password:      "N0_L0WER_CAS&-",
		},
		{
			testName:      "Fail: No special char",
			expectSuccess: false,
			password:      "thereIsN0Sp3ci4lChars",
		},
		{
			testName:      "Fail: No digit",
			expectSuccess: false,
			password:      "Missing_digits?",
		},
		{
			testName:      "Fail: Too short",
			expectSuccess: false,
			password:      "Tet-1",
		},
		{
			testName:          "Fail: Unauthorized word",
			expectSuccess:     false,
			password:          "FckTh1sSh!t",
			unauthorizedWords: []string{"FckTh1sSh!t"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			passwordValidation := validation.NewPasswordValidation()
			if tt.minLength != 0 {
				passwordValidation.SetMinLength(tt.minLength)
			}
			if len(tt.unauthorizedWords) > 0 {
				passwordValidation.SetUnauthorizedWords(tt.unauthorizedWords)
			}

			validPassword := passwordValidation.IsPasswordStrengthEnough(tt.password)
			if tt.expectSuccess != validPassword {
				t.Fatalf("The password has the valid status (%v), while %v was expected", validPassword, tt.expectSuccess)
			}
		})
	}

}
