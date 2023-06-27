/**
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cache

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func (b *DiffBaseDataSet) addNATGateway(dbItem *mysql.NATGateway, seq int) {
	b.NATGateways[dbItem.Lcuuid] = &NATGateway{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:         dbItem.Name,
		FloatingIPs:  dbItem.FloatingIPs,
		RegionLcuuid: dbItem.Region,
	}
	b.GetLogFunc()(addDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, b.NATGateways[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteNATGateway(lcuuid string) {
	delete(b.NATGateways, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, lcuuid))
}

type NATGateway struct {
	DiffBase
	Name         string `json:"name"`
	FloatingIPs  string `json:"floating_ips"`
	RegionLcuuid string `json:"region_lcuuid"`
}

func (n *NATGateway) Update(cloudItem *cloudmodel.NATGateway) {
	n.Name = cloudItem.Name
	n.FloatingIPs = cloudItem.FloatingIPs
	n.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_NAT_GATEWAY_EN, n))
}
