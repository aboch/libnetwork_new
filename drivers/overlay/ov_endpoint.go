package overlay

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netutils"
)

type endpointTable map[string]*endpoint

type endpoint struct {
	id   string
	mac  net.HardwareAddr
	addr *net.IPNet
}

func (n *network) endpoint(eid string) *endpoint {
	n.Lock()
	defer n.Unlock()

	return n.endpoints[eid]
}

func (n *network) addEndpoint(ep *endpoint) {
	n.Lock()
	n.endpoints[ep.id] = ep
	n.Unlock()
}

func (n *network) deleteEndpoint(eid string) {
	n.Lock()
	delete(n.endpoints, eid)
	n.Unlock()
}

func (d *driver) CreateEndpoint(nid, eid string, ifInfo driverapi.InterfaceInfo,
	epOptions map[string]interface{}) error {
	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	ep := &endpoint{
		id: eid,
	}

	if ifInfo != nil {
		ep.addr = ifInfo.Address()
		ep.mac = ifInfo.MacAddress()
		n.addEndpoint(ep)
		return nil
	}

	ipID, err := d.ipAllocator.GetID()
	if err != nil {
		return fmt.Errorf("could not allocate ip from subnet %s: %v",
			bridgeSubnet.String(), err)
	}

	ep.addr = &net.IPNet{
		Mask: bridgeSubnet.Mask,
	}
	ep.addr.IP = make([]byte, 4)

	binary.BigEndian.PutUint32(ep.addr.IP, bridgeSubnetInt+ipID)

	ep.mac = netutils.GenerateMACFromIP(ep.addr.IP)

	err = ifInfo.SetMacAddress(ep.mac)
	if err != nil {
		return err
	}
	err = ifInfo.SetIPAddress(ep.addr)
	if err != nil {
		return err
	}

	n.addEndpoint(ep)

	return nil
}

func (d *driver) DeleteEndpoint(nid, eid string) error {
	if err := validateID(nid, eid); err != nil {
		return err
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("network id %q not found", nid)
	}

	ep := n.endpoint(eid)
	if ep == nil {
		return fmt.Errorf("endpoint id %q not found", eid)
	}

	d.ipAllocator.Release(binary.BigEndian.Uint32(ep.addr.IP) - bridgeSubnetInt)
	n.deleteEndpoint(eid)
	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	return make(map[string]interface{}, 0), nil
}
