package utils

// ChanSuffix Suffixes all items in a string channel with a given suffix
func ChanSuffix(in chan string, suffix string, orig bool) chan string {
	out := make(chan string)
	go func() {
		for domain := range in {
			if domain == "" {
				continue
			}

			//logger.Debugf("aliasing domain=%s with suffix=%s", domain, suffix)
			out <- domain + suffix
			if orig {
				out <- domain
			}
		}
		close(out)
	}()
	return out
}
