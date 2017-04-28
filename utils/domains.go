package utils

import "strings"

// DomainJoin Joins N portions of a domain by "."
func DomainJoin(parts ...string) string {
	return strings.Join(parts, ".")
}

// IsDomainEnded Checks if domain has ending "."
func IsDomainEnded(domain string) bool {
	return strings.HasSuffix(domain, ".")
}

func Reverse(input []string) []string {
	if len(input) == 0 {
		return input
	}

	return append(Reverse(input[1:]), input[0])
}
