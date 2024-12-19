/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2023.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import "github.com/siemens/GoScans/utils"

var inventories = make(map[string]Inventory)

type Inventory interface {
	Init(logger utils.Logger, conf map[string]map[string]string) error
	Initialized() bool
	ByIp(logger utils.Logger, ip string) (company string, department string, owner string, hostnames []string, ips []string, critical bool, err error)
	ByFqdn(logger utils.Logger, hostname string, expectedIps []string) (company string, department string, owner string, hostnames []string, ips []string, critical bool, err error)
}

func InitInventories(logger utils.Logger, config map[string]map[string]string) error {
	for _, inventory := range inventories {
		err := inventory.Init(logger, config)
		if err != nil {
			return err
		}
	}
	return nil
}
