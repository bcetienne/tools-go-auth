package validation

import "regexp"

type EmailValidation struct {
	emailRegex *regexp.Regexp
}

type EmailValidationInterface interface {
	IsValidEmail(email string) bool
}

func NewEmailValidation() EmailValidation {
	return EmailValidation{
		emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
	}
}

func (ev *EmailValidation) IsValidEmail(email string) bool {
	return ev.emailRegex.MatchString(email)
}
