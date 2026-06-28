package util

import (
	"errors"
	"regexp"
	"strings"
)

var scopeRegex = regexp.MustCompile(`^[a-zA-Z0-9_:./|-]+$`)

// ValidateScope 验证 scope 格式 (§8.5.5)
func ValidateScope(scope string) error {
	if scope == "" {
		return errors.New("scope cannot be empty")
	}

	scopes := strings.Fields(scope)
	for _, s := range scopes {
		if !scopeRegex.MatchString(s) {
			return errors.New("invalid scope format: " + s)
		}
	}

	return nil
}

// ExtractAudienceFromScope 从 scope 中提取 audience (§8.5.5)
func ExtractAudienceFromScope(scope string) (string, error) {
	scopes := strings.Fields(scope)
	for _, s := range scopes {
		if strings.HasPrefix(s, "audience:") {
			return s[9:], nil
		}
	}
	return "", errors.New("no audience found in scope")
}
