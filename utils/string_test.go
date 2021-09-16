/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"reflect"
	"strings"
	"testing"
)

func TestRemoveDuplicates(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		elements []string
		want     []string
	}{
		{"duplicates1", []string{"a", "b", "a", "a", "c"}, []string{"a", "b", "c"}},
		{"duplicates2", []string{"a", "a"}, []string{"a"}},
		{"duplicates3", []string{"a", "  ", "  ", "c"}, []string{"a", "  ", "c"}},
		{"no-duplicates1", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"no-duplicates2", []string{"a", "A", "aA"}, []string{"a", "A", "aA"}},
		{"no-duplicates3", []string{"a", "  ", "   ", "c"}, []string{"a", "  ", "   ", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UniqueStrings(tt.elements); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UniqueStrings() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestTrimToLower(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name  string
		slice []string
		want  []string
	}{
		{"all-upper", []string{"A", "B", "C"}, []string{"a", "b", "c"}},
		{"mixed-upper", []string{"A", "b", "C"}, []string{"a", "b", "c"}},
		{"mixed-upper-untrimmed1", []string{"A", "b ", "C"}, []string{"a", "b", "c"}},
		{"mixed-upper-untrimmed2", []string{" A ", "b ", " C"}, []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimToLower(tt.slice); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimToLower() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestShuffle(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		strings []string
	}{
		{"new!=old", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
		{"new!=old", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Shuffle(tt.strings); reflect.DeepEqual(got, tt.strings) {
				t.Errorf("Shuffle() = '%v', DON'T want = '%v'", got, tt.strings)
			}
		})
	}
}

func TestFilter(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		input  []string
		filter func(string) bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"a-only", args{[]string{"a", "b", "A", "a", "a", "c"}, func(s string) bool { return s == "a" }}, []string{"a", "a", "a"}},
		{"a-containing", args{[]string{"Anton", "Berta", "Caesar", "Doris", "Esat", "Friedrich"}, func(s string) bool { return strings.Contains(s, "a") }}, []string{"Berta", "Caesar", "Esat"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Filter(tt.args.input, tt.args.filter); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Filter() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestReverse(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"valid", []string{"7", "6", "5", "A", "3", "2", "1", "0"}, []string{"0", "1", "2", "3", "A", "5", "6", "7"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reverse(tt.input)
			if !reflect.DeepEqual(tt.input, tt.want) {
				t.Errorf("Reverse() = '%v', want = '%v'", tt.input, tt.want)
			}
		})
	}
}

func TestAlter(t *testing.T) {
	manipulatorFunc := func(elem string) string { return "'" + elem + "'" }

	// Prepare and run test cases
	type args struct {
		slice       []string
		manipulator func(string) string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"sample", args{[]string{"1", "1", "2"}, manipulatorFunc}, []string{"'1'", "'1'", "'2'"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Map(tt.args.slice, tt.args.manipulator); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Map() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestStrContained(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		candidate string
		slices    [][]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"one-slice-contained", args{"test", [][]string{{"a", "b", "c", "test"}}}, true},
		{"one-slice-not-contained", args{"test", [][]string{{"a", "b", "c", "d"}}}, false},

		{"multiple-slices-contained", args{"test", [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "test"}, {"a", "b", "c", "d"}}}, true},
		{"multiple-slices-not-contained", args{"test", [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "e"}, {"a", "b", "c", "d"}}}, false},

		{"known-1", args{"test1", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, true},
		{"known-2", args{"test1", [][]string{{"test1", "test2", "test3"}, {"test1", "test2", "test3"}}}, true},
		{"known-3", args{"probe1", [][]string{{}, {"probe1", "probe2", "probe3"}}}, true},
		{"unknown-1", args{"test4", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-2", args{"test", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-3", args{"test", [][]string{{}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-4", args{"test", [][]string{{}, {}}}, false},
		{"unknown-5", args{"test", [][]string{{}}}, false},
		{"unknown-6", args{"test", [][]string{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StrContained(tt.args.candidate, tt.args.slices...); got != tt.want {
				t.Errorf("StrContained() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestSubstrContained(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		candidate string
		slices    [][]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"multiple-slices-contained", args{"test", [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "test"}, {"a", "b", "c", "d"}}}, true},
		{"multiple-slices-not-contained", args{"test", [][]string{{"a", "b", "c", "d"}, {"a", "b", "c", "d"}, {"a", "b", "c", "e"}, {"a", "b", "c", "d"}}}, false},

		{"known-substr-1", args{"obe2", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, true},
		{"known-substr-2", args{"test", [][]string{{"test1", "test2", "test3"}, {"test1", "test2", "test3"}}}, true},
		{"known-substr-3", args{"e2", [][]string{{}, {"probe1", "probe2", "probe3"}}}, true},
		{"unknown-substr-1", args{"test5", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-substr-2", args{"5", [][]string{{"test1", "test2", "test3"}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-substr-3", args{"other", [][]string{{}, {"probe1", "probe2", "probe3"}}}, false},
		{"unknown-substr-4", args{"other", [][]string{{}, {}}}, false},
		{"unknown-substr-5", args{"other", [][]string{{}}}, false},
		{"unknown-substr-6", args{"other", [][]string{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SubstrContained(tt.args.candidate, tt.args.slices...); got != tt.want {
				t.Errorf("StrContained() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestSameElementsSlices(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice1 []string
		slice2 []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"both empty", args{[]string{}, []string{}}, true},
		{"both nil", args{nil, nil}, true},
		{"same one elem", args{[]string{"ab"}, []string{"ab"}}, true},
		{"same three elem", args{[]string{"a", "b", "c"}, []string{"a", "b", "c"}}, true},
		{"same elem diff order", args{[]string{"a", "b", "a"}, []string{"b", "a", "a"}}, true},
		{"one nil", args{nil, []string{"a"}}, false},
		{"one nil2", args{[]string{"a"}, nil}, false},
		{"one nil one empty", args{nil, []string{}}, false},
		{"diff elem", args{[]string{"a", "b"}, []string{"a", "c"}}, false},
		{"diff elem2", args{[]string{"a", "a"}, []string{"a", "c"}}, false},
		{"diff amount", args{[]string{"a"}, []string{"a", "c"}}, false},
		{"same elem diff amount", args{[]string{"a", "b", "a"}, []string{"a", "b", "b"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Equals(tt.args.slice1, tt.args.slice2); got != tt.want {
				t.Errorf("EqualSlices() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice    []string
		elements []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"empty", args{[]string{}, []string{}}, []string{}},
		{"all-duplicates", args{[]string{"1", "2", "3"}, []string{"1", "2", "3"}}, []string{"1", "2", "3"}},
		{"most-duplicates", args{[]string{"1", "2", "3"}, []string{"1", "2", "3", "4"}}, []string{"1", "2", "3", "4"}},
		{"one-to-one", args{[]string{"1"}, []string{"2"}}, []string{"1", "2"}},
		{"three-to-none", args{[]string{}, []string{"1", "2", "3"}}, []string{"1", "2", "3"}},
		{"none-to-three", args{[]string{"1", "2", "3"}, []string{}}, []string{"1", "2", "3"}},
		{"duplicates-to-none", args{[]string{}, []string{"1", "2", "3", "3", "3"}}, []string{"1", "2", "3"}},
		{"duplicates-to-duplicates", args{[]string{"1", "1", "1", "1"}, []string{"1", "2", "3", "3", "3"}}, []string{"1", "1", "1", "1", "2", "3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AppendUnique(tt.args.slice, tt.args.elements...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AppendUnique() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestRemoveFromSlice(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		slice []string
		s     string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"empty", args{[]string{}, "3"}, nil},
		{"no-occurrence", args{[]string{"1", "2"}, "3"}, []string{"1", "2"}},
		{"one-occurrence", args{[]string{"1", "2", "3"}, "3"}, []string{"1", "2"}},
		{"multiple-occurrences", args{[]string{"3", "1", "3", "3", "2", "3"}, "3"}, []string{"1", "2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveFromSlice(tt.args.slice, tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveFromSlice() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestTitleFirstLetter(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"multiple words", args{"this is a sentence."}, "This is a sentence."},
		{"empty string", args{""}, ""},
		{"uppercase already", args{"The bear"}, "The bear"},
		{"one letter", args{"x"}, "X"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TitleFirstLetter(tt.args.s); got != tt.want {
				t.Errorf("TitleFirstLetter() = %v, want %v", got, tt.want)
			}
		})
	}
}
