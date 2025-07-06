package validation

import (
	"regexp"
	"slices"
)

type PasswordValidation struct {
	minLength         int
	unauthorizedWords []string
	lowercaseRegex    *regexp.Regexp
	uppercaseRegex    *regexp.Regexp
	digitRegex        *regexp.Regexp
	specialCharRegex  *regexp.Regexp
}

type PasswordValidationInterface interface {
	SetMinLength(minLength int)
	SetUnauthorizedWords(unauthorizedWords []string)
	PasswordContainsLowercase(password string) bool
	PasswordContainsUppercase(password string) bool
	PasswordContainsDigit(password string) bool
	PasswordContainsSpecialChar(password string) bool
	PasswordHasMinLength(password string) bool
	PasswordContainsUnauthorizedWord(password string) bool
	IsPasswordStrengthEnough(password string) bool
}

func NewPasswordValidation() PasswordValidation {
	passwordValidation := PasswordValidation{
		minLength:         8,
		unauthorizedWords: []string{},
		lowercaseRegex:    regexp.MustCompile(`[a-z]`),
		uppercaseRegex:    regexp.MustCompile(`[A-Z]`),
		digitRegex:        regexp.MustCompile(`\d`),
		specialCharRegex:  regexp.MustCompile(`[!@#$%^&*()\-+={}[\]|\\:;"'<>,.?/~` + "`" + `_]`),
	}
	return passwordValidation
}

func (pv *PasswordValidation) SetMinLength(minLength int) {
	// Avoid skip the minimum security requirements
	if minLength < 8 {
		return
	}
	pv.minLength = minLength
}

func (pv *PasswordValidation) SetUnauthorizedWords(unauthorizedWords []string) {
	pv.unauthorizedWords = unauthorizedWords
}

func (pv *PasswordValidation) PasswordContainsLowercase(password string) bool {
	return pv.lowercaseRegex.MatchString(password)
}

func (pv *PasswordValidation) PasswordContainsUppercase(password string) bool {
	return pv.uppercaseRegex.MatchString(password)
}

func (pv *PasswordValidation) PasswordContainsDigit(password string) bool {
	return pv.digitRegex.MatchString(password)
}

func (pv *PasswordValidation) PasswordContainsSpecialChar(password string) bool {
	return pv.specialCharRegex.MatchString(password)
}

func (pv *PasswordValidation) PasswordHasMinLength(password string) bool {
	return len(password) >= pv.minLength
}

func (pv *PasswordValidation) PasswordContainsUnauthorizedWord(password string) bool {
	if len(pv.unauthorizedWords) == 0 {
		return false
	}
	return slices.Contains(pv.unauthorizedWords, password)
}

func (pv *PasswordValidation) IsPasswordStrengthEnough(password string) bool {
	return pv.PasswordContainsLowercase(password) &&
		pv.PasswordContainsUppercase(password) &&
		pv.PasswordContainsDigit(password) &&
		pv.PasswordContainsSpecialChar(password) &&
		!pv.PasswordContainsUnauthorizedWord(password) &&
		pv.PasswordHasMinLength(password)
}
