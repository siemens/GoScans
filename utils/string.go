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
	"math/rand"
	"strings"
)

// UniqueStrings gets rid of redundant elements
func UniqueStrings(elements []string) []string {

	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	var result []string

	// Iterate elements and add them to the new slice if they were not seen before
	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}

	// Return the new slice.
	return result
}

// AppendUnique adds elements to an existing slice which are not contained yet. If the original slice already has
// duplicates in it, they will remain.
func AppendUnique(slice []string, elements ...string) []string {

	// Prepare lookup table
	lookup := make(map[string]struct{}, len(slice))
	for _, e := range slice {
		lookup[e] = struct{}{}
	}

	// Append elements that are not already contained
	for _, element := range elements {
		_, contained := lookup[element]
		if !contained {
			lookup[element] = struct{}{}
			slice = append(slice, element)
		}
	}

	// Returned appended slice
	return slice
}

// TrimToLower converts slice elements to lower case and trim whitespaces
func TrimToLower(slice []string) []string {
	var trimmedLowerSlice []string
	for _, item := range slice {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, ".") // Remove . of DNS domain names
		item = strings.ToLower(item)
		trimmedLowerSlice = append(trimmedLowerSlice, item)
	}
	return trimmedLowerSlice
}

// Shuffle randomizes slice of strings
func Shuffle(strings []string) []string {
	r := rand.New(rand.NewSource(int64(rand.Int())))
	ret := make([]string, len(strings))
	perm := r.Perm(len(strings))
	for i, randIndex := range perm {
		ret[i] = strings[randIndex]
	}
	return ret
}

// Filter filters slice for elements where the given function returns true
func Filter(input []string, filter func(string) bool) []string {
	vsf := make([]string, 0, len(input))
	for _, v := range input {
		if filter(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
}

// Reverse orders slice in reverse order
func Reverse(input []string) {
	for i := len(input)/2 - 1; i >= 0; i-- {
		opp := len(input) - 1 - i
		input[i], input[opp] = input[opp], input[i]
	}
}

// Map applies a manipulation function to each element of a slice
func Map(slice []string, fn func(string) string) []string {
	alteredElements := make([]string, len(slice))
	for i, item := range slice {
		alteredElements[i] = fn(item)
	}
	return alteredElements
}

// StrContained checks whether a given (exact) value is contained within one or multiple given slices
func StrContained(candidate string, slices ...[]string) bool {

	// Translate strings into map for faster lookups
	items := make(map[string]struct{})
	for _, slice := range slices {
		for _, item := range slice {
			items[item] = struct{}{}
		}
	}

	// Search items for candidate
	_, ok := items[candidate]
	if ok {
		return true
	}

	// Return false as item was not found in candidates
	return false
}

// Checks whether a given substring can be found within the strings within the given slices. This
// function is like StrContained but not looking for *exact* matches.
func SubstrContained(candidate string, slices ...[]string) bool {
	for _, slice := range slices {
		for _, item := range slice {
			if strings.Contains(item, candidate) {
				return true
			}
		}
	}
	return false
}

// Check if two slices of strings contain the same elements and also the same amount of those,
// but with no regard to their order
// []string{"a","a","c"} == []string{"c","a","c"} >>> false
// []string{"z","z","x"} == []string{"x","z","z"} >>> true
func Equals(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	if (s1 == nil) != (s2 == nil) {
		return false
	}
	s1Map := make(map[string]int)
	s2Map := make(map[string]int)
	for _, s1Str := range s1 {
		s1Map[s1Str]++
	}
	for _, s2Str := range s2 {
		s2Map[s2Str]++
	}
	for s1MapKey, s1MapVal := range s1Map {
		if s2Map[s1MapKey] != s1MapVal {
			return false
		}
	}
	return true
}

// RemoveFromSlice removes a given element (and potential duplicates) from a slice and returns a new slice
func RemoveFromSlice(list []string, s string) []string {

	var retList []string

	// Generate new slice dropping requested strings
	for _, current := range list {
		if current == s {
			continue
		} else {
			retList = append(retList, current)
		}
	}

	// Return new filtered slice
	return retList
}

// Makes the fist letter (and only the first letter) of the string uppercase
func TitleFirstLetter(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}
