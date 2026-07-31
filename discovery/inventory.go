/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import "github.com/siemens/GoScans/utils"

// inventories registers the available inventory implementations
var inventories = make(map[string]Inventory)

// Inventory defines the interface that all asset inventory backends must implement.
type Inventory interface {
	Init(logger utils.Logger, conf map[string]map[string]string) error
	Initialized() bool
	ByIp(logger utils.Logger, ip string) (company string, department string, owner string, hostnames []string, ips []string, critical bool, err error)
	ByFqdn(logger utils.Logger, hostname string, expectedIps []string) (company string, department string, owner string, hostnames []string, ips []string, critical bool, err error)
}

// InitInventories initializes all registered inventory backends with the provided configuration.
func InitInventories(logger utils.Logger, config map[string]map[string]string) error {

	// Initialize each registered inventory
	for _, inventory := range inventories {
		errInit := inventory.Init(logger, config)
		if errInit != nil {
			return errInit
		}
	}

	// Return nil as everything went fine
	return nil
}
