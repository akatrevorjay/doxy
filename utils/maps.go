package utils

import (
	"strings"
)

func FilterMappingByPrefix(in map[string]string, prefix string, strip bool) (out map[string]string) {
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
