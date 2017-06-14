package utils

import "strings"

// DomainJoin Joins N portions of a domain by "."
func DomainJoin(parts ...string) string {
	return strings.Join(parts, ".")
}

func DomainSplit(str string) []string {
	return strings.Split(str, ".")
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

// IsPrefixQuery is used to determine whether "query" is a potential prefix
// query for "name". It allows for wildcards (*) in the query. However is makes
// one exception to accomodate the desired behavior we wish from doxy,
// namely, the query may be longer than "name" and still be a valid prefix
// query for "name".
// Examples:
//   foo.bar.baz.qux is a valid query for bar.baz.qux (longer prefix is okay)
//   foo.*.baz.qux   is a valid query for bar.baz.qux (wildcards okay)
//   *.baz.qux       is a valid query for baz.baz.qux (wildcard prefix okay)
func IsPrefixQuery(query, name []string) bool {
	for i, j := len(query)-1, len(name)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if query[i] != name[j] && query[i] != "*" {
			return false
		}
	}
	return true
}
