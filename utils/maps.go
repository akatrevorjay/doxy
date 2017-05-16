package utils

import (
	"strings"
)

// TODO This should be a channel.
// FilterMappingByKeyPrefix Filters a mapping by a key prefix
func FilterMappingByKeyPrefix(in map[string]string, prefix string, strip bool) map[string]string {
	out := make(map[string]string)

	for k, v := range in {
		if !strings.HasPrefix(k, prefix) {
			continue
		}

		if strip {
			k = k[len(prefix):]
		}

		out[k] = v
	}

	return out
}

func HasKeys(mapping map[string]string, keys []string) bool {
	for _, k := range keys {
		_, ok := mapping[k]
		if !ok {
			return false
		}
	}
	return true
}
