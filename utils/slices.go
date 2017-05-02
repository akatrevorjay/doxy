package utils

// NewSlice : Create a slice containing a range of elements.
//
//  start: First value of the sequence.
//  end:   The sequence is ended upon reaching the end value.
//  step:  step will be used as the increment between elements in the sequence.
//		   step should be given as a positive, negative or zero number.
//
//	returns: Slice of elements from start to end over step, inclusive.
func newIntSlice(start, count, step int) []int {
	s := make([]int, count)
	for i := range s {
		s[i] = start
		start += step
	}
	return s
}

func unpack(s []string, vars ...*string) {
	for i, str := range s {
		*vars[i] = str
	}
}
