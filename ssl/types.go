/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

//go:generate stringer types_certificate.go types_cipher.go

// DON'T ALTER THE COMMENTS for struct fields!

// Designing the Type definitions was a delicate task. So here's the reasoning behind it:
// We want to have some validity checks on variables that we get from the x509 package or SSLyze. Otherwise we'd have
// no chance at all to realize any changes to those variables.

// Ciphers:
// As we have created the mapping by our selves, we could simply use the (string) names provided in a mapping.
// This would be alright, but would make it hard to change the naming as the whole mapping would have to be adapted.
// Additionally we still would need to create the validity checks in order to recognize typos or the like. So we would
// still need to define constants and call the check function (or a constructor that checks the input for what it's worth).
// Therefore we can also create constants and use them in the mapping. This provides the additional option to use small
// integers to get a small performance boost. These constants have a custom type which can be checked for validity
// if needed rather than having a constructor, as this constructor would no guarantee any valid values after all -
// at least without a massive amount of boilerplate code (See https://stackoverflow.com/a/17989915/10315806).

// Certificates:
// The reasoning behind the types provided by types_certificate.go is similar with the small difference that we have to
// provide constructors for the types.
// We need those constructors because we currently let the x509 package parse the certificates and subsequently retrieve
// information from the results. Therefore we would be bound to the provided naming and wouldn't be able to create new
// methods. This is why we again create our own custom types. Additionally providing our own constructors gives us the
// possibility to conveniently extend the types in the future. An example would be the GOST keys provided in some
// certificates.
// We don't provide any custom types for the 'KeyUsage' and 'ExtKeyUsage', because we don't need further process them
// at this point (i.e. additional methods). Therefore we only create a custom mapping to a corresponding string.

// String representation (code generation):
// As the code for the string representation of our types is quite cumbersome, it is located in a separate file and
// auto-generated. Running the generator is only needed if the existing types (including their naming) are changed or
// new types that need a string representation are added. In order to re-generate the String() function run the command
// in this file. If you use the command line rather than the IDE, you need to make sure the stringer package is in your
// PATH. When you added a new type make sure to list it in the corresponding command (at the top of types_certificate.go
// or types_cipher.go) and re-run the command.
// Currently stringer simply USES THE COMMENT after every constant as their string representation.
