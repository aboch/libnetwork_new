package libnetwork

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/etchosts"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/types"
)

// A Network represents a logical connectivity zone that containers may
// join using the Link method. A Network is managed by a specific driver.
type Network interface {
	// A user chosen name for this network.
	Name() string

	// A system generated id for this network.
	ID() string

	// The type of network, which corresponds to its managing driver.
	Type() string

	// Create a new endpoint to this network symbolically identified by the
	// specified unique name. The options parameter carry driver specific options.
	// Labels support will be added in the near future.
	CreateEndpoint(name string, options ...EndpointOption) (Endpoint, error)

	// Delete the network.
	Delete() error

	// Endpoints returns the list of Endpoint(s) in this network.
	Endpoints() []Endpoint

	// WalkEndpoints uses the provided function to walk the Endpoints
	WalkEndpoints(walker EndpointWalker)

	// EndpointByName returns the Endpoint which has the passed name. If not found, the error ErrNoSuchEndpoint is returned.
	EndpointByName(name string) (Endpoint, error)

	// EndpointByID returns the Endpoint which has the passed id. If not found, the error ErrNoSuchEndpoint is returned.
	EndpointByID(id string) (Endpoint, error)
}

// EndpointWalker is a client provided function which will be used to walk the Endpoints.
// When the function returns true, the walk will stop.
type EndpointWalker func(ep Endpoint) bool

type svcMap map[string]net.IP

// IpamConf contains all the ipam related configurations for a network
type IpamConf struct {
	AddressSpace   string
	PreferredPool  string
	SubPool        string
	Options        map[string]string // IPAM options
	IsV6           bool
	ReserveGateway bool // Tells libnetwork to reserve the gw
}

// ipamInfo contains all the ipam related operational info for a network
type ipamInfo struct {
	poolID  string
	gateway *net.IPNet
	ipamapi.IPData
}

type network struct {
	ctrlr       *controller
	name        string
	networkType string
	id          string
	ipamType    string
	driver      driverapi.Driver
	ipamConfig  []IpamConf
	ipamInfo    []ipamInfo
	enableIPv6  bool
	endpointCnt uint64
	endpoints   endpointTable
	generic     options.Generic
	dbIndex     uint64
	svcRecords  svcMap
	dbExists    bool
	persist     bool
	stopWatchCh chan struct{}
	dataScope   datastore.DataScope
	sync.Mutex
}

func (n *network) Name() string {
	n.Lock()
	defer n.Unlock()

	return n.name
}

func (n *network) ID() string {
	n.Lock()
	defer n.Unlock()

	return n.id
}

func (n *network) Type() string {
	n.Lock()
	defer n.Unlock()

	if n.driver == nil {
		return ""
	}

	return n.driver.Type()
}

func (n *network) Key() []string {
	n.Lock()
	defer n.Unlock()
	return []string{datastore.NetworkKeyPrefix, n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{datastore.NetworkKeyPrefix}
}

func (n *network) Value() []byte {
	n.Lock()
	defer n.Unlock()
	b, err := json.Marshal(n)
	if err != nil {
		return nil
	}
	return b
}

func (n *network) SetValue(value []byte) error {
	return json.Unmarshal(value, n)
}

func (n *network) Index() uint64 {
	n.Lock()
	defer n.Unlock()
	return n.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.Lock()
	n.dbIndex = index
	n.dbExists = true
	n.Unlock()
}

func (n *network) Exists() bool {
	n.Lock()
	defer n.Unlock()
	return n.dbExists
}

func (n *network) Skip() bool {
	n.Lock()
	defer n.Unlock()
	return !n.persist
}

func (n *network) DataScope() datastore.DataScope {
	n.Lock()
	defer n.Unlock()
	return n.dataScope
}

func (n *network) EndpointCnt() uint64 {
	n.Lock()
	defer n.Unlock()
	return n.endpointCnt
}

func (n *network) IncEndpointCnt() {
	n.Lock()
	n.endpointCnt++
	n.Unlock()
}

func (n *network) DecEndpointCnt() {
	n.Lock()
	n.endpointCnt--
	n.Unlock()
}

// TODO : Can be made much more generic with the help of reflection (but has some golang limitations)
func (n *network) MarshalJSON() ([]byte, error) {
	netMap := make(map[string]interface{})
	netMap["name"] = n.name
	netMap["id"] = n.id
	netMap["networkType"] = n.networkType
	netMap["ipamType"] = n.ipamType
	netMap["endpointCnt"] = n.endpointCnt
	netMap["enableIPv6"] = n.enableIPv6
	netMap["generic"] = n.generic
	netMap["persist"] = n.persist
	return json.Marshal(netMap)
}

// TODO : Can be made much more generic with the help of reflection (but has some golang limitations)
func (n *network) UnmarshalJSON(b []byte) (err error) {
	var netMap map[string]interface{}
	if err := json.Unmarshal(b, &netMap); err != nil {
		return err
	}
	n.name = netMap["name"].(string)
	n.id = netMap["id"].(string)
	n.ipamType = netMap["ipamType"].(string)
	n.networkType = netMap["networkType"].(string)
	n.endpointCnt = uint64(netMap["endpointCnt"].(float64))
	n.enableIPv6 = netMap["enableIPv6"].(bool)
	if netMap["generic"] != nil {
		n.generic = netMap["generic"].(map[string]interface{})
	}
	if netMap["persist"] != nil {
		n.persist = netMap["persist"].(bool)
	}
	return nil
}

// NetworkOption is a option setter function type used to pass varios options to
// NewNetwork method. The various setter functions of type NetworkOption are
// provided by libnetwork, they look like NetworkOptionXXXX(...)
type NetworkOption func(n *network)

// NetworkOptionGeneric function returns an option setter for a Generic option defined
// in a Dictionary of Key-Value pair
func NetworkOptionGeneric(generic map[string]interface{}) NetworkOption {
	return func(n *network) {
		n.generic = generic
		if _, ok := generic[netlabel.EnableIPv6]; ok {
			n.enableIPv6 = generic[netlabel.EnableIPv6].(bool)
		}
	}
}

// NetworkOptionPersist returns an option setter to set persistence policy for a network
func NetworkOptionPersist(persist bool) NetworkOption {
	return func(n *network) {
		n.persist = persist
	}
}

// NetworkOptionIpam function returns an option setter for the ipam configuration for this network
func NetworkOptionIpam(ipamDriver string, configs []IpamConf) NetworkOption {
	return func(n *network) {
		n.ipamType = ipamDriver
		n.ipamConfig = configs
	}
}

func (n *network) processOptions(options ...NetworkOption) {
	for _, opt := range options {
		if opt != nil {
			opt(n)
		}
	}
}

func (n *network) Delete() error {
	var err error

	ctrlr := n.getController()

	ctrlr.Lock()
	_, ok := ctrlr.networks[n.id]
	ctrlr.Unlock()

	if !ok {
		return &UnknownNetworkError{name: n.name, id: n.id}
	}

	numEps := n.EndpointCnt()
	if numEps != 0 {
		return &ActiveEndpointsError{name: n.name, id: n.id}
	}

	// deleteNetworkFromStore performs an atomic delete operation and the network.endpointCnt field will help
	// prevent any possible race between endpoint join and network delete
	if err = ctrlr.deleteFromStore(n); err != nil {
		if err == datastore.ErrKeyModified {
			return types.InternalErrorf("operation in progress. delete failed for network %s. Please try again.")
		}
		return err
	}

	defer func() {
		if err != nil {
			n.dbExists = false
			if e := ctrlr.updateToStore(n); e != nil {
				log.Warnf("failed to recreate network in store %s : %v", n.name, e)
			}
		}
	}()

	if err = n.deleteNetwork(); err != nil {
		return err
	}

	n.ipamRelease()

	return nil
}

func (n *network) deleteNetwork() error {
	n.Lock()
	id := n.id
	d := n.driver
	n.ctrlr.Lock()
	delete(n.ctrlr.networks, id)
	n.ctrlr.Unlock()
	n.Unlock()

	if err := d.DeleteNetwork(n.id); err != nil {
		// Forbidden Errors should be honored
		if _, ok := err.(types.ForbiddenError); ok {
			n.ctrlr.Lock()
			n.ctrlr.networks[n.id] = n
			n.ctrlr.Unlock()
			return err
		}
		log.Warnf("driver error deleting network %s : %v", n.name, err)
	}
	n.stopWatch()
	return nil
}

func (n *network) addEndpoint(ep *endpoint) error {
	var err error
	n.Lock()
	n.endpoints[ep.id] = ep
	d := n.driver
	n.Unlock()

	defer func() {
		if err != nil {
			n.Lock()
			delete(n.endpoints, ep.id)
			n.Unlock()
		}
	}()

	err = d.CreateEndpoint(n.id, ep.id, ep.Interface(), ep.generic)
	if err != nil {
		return types.InternalErrorf("failed to create endpoint %s on network %s: %v", ep.Name(), n.Name(), err)
	}

	n.updateSvcRecord(ep, true)
	return nil
}

func (n *network) CreateEndpoint(name string, options ...EndpointOption) (Endpoint, error) {
	var err error
	if !config.IsValidName(name) {
		return nil, ErrInvalidName(name)
	}

	if _, err = n.EndpointByName(name); err == nil {
		return nil, types.ForbiddenErrorf("service endpoint with name %s already exists", name)
	}

	ep := &endpoint{name: name, generic: make(map[string]interface{}), iface: &endpointInterface{}}
	ep.id = stringid.GenerateRandomID()
	ep.network = n
	ep.processOptions(options...)

	if err = ep.assignAddress(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ep.releaseAddress()
		}
	}()

	ctrlr := n.getController()

	n.IncEndpointCnt()
	if err = ctrlr.updateToStore(n); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			n.DecEndpointCnt()
			if err = ctrlr.updateToStore(n); err != nil {
				log.Warnf("endpoint count cleanup failed when updating network for %s : %v", name, err)
			}
		}
	}()
	if err = n.addEndpoint(ep); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if e := ep.Delete(); ep != nil {
				log.Warnf("cleaning up endpoint failed %s : %v", name, e)
			}
		}
	}()

	if !ep.isLocalScoped() {
		if err = ctrlr.updateToStore(ep); err != nil {
			return nil, err
		}
	}

	return ep, nil
}

func (n *network) Endpoints() []Endpoint {
	n.Lock()
	defer n.Unlock()
	list := make([]Endpoint, 0, len(n.endpoints))
	for _, e := range n.endpoints {
		list = append(list, e)
	}

	return list
}

func (n *network) WalkEndpoints(walker EndpointWalker) {
	for _, e := range n.Endpoints() {
		if walker(e) {
			return
		}
	}
}

func (n *network) EndpointByName(name string) (Endpoint, error) {
	if name == "" {
		return nil, ErrInvalidName(name)
	}
	var e Endpoint

	s := func(current Endpoint) bool {
		if current.Name() == name {
			e = current
			return true
		}
		return false
	}

	n.WalkEndpoints(s)

	if e == nil {
		return nil, ErrNoSuchEndpoint(name)
	}

	return e, nil
}

func (n *network) EndpointByID(id string) (Endpoint, error) {
	if id == "" {
		return nil, ErrInvalidID(id)
	}
	n.Lock()
	defer n.Unlock()
	if e, ok := n.endpoints[id]; ok {
		return e, nil
	}
	return nil, ErrNoSuchEndpoint(id)
}

func (n *network) isGlobalScoped() bool {
	return n.DataScope() == datastore.GlobalScope
}

func (n *network) updateSvcRecord(ep *endpoint, isAdd bool) {
	n.Lock()
	var recs []etchosts.Record
	if iface := ep.Iface(); iface.Address() != nil {
		if isAdd {
			n.svcRecords[ep.Name()] = iface.Address().IP
			n.svcRecords[ep.Name()+"."+n.name] = iface.Address().IP
		} else {
			delete(n.svcRecords, ep.Name())
			delete(n.svcRecords, ep.Name()+"."+n.name)
		}

		recs = append(recs, etchosts.Record{
			Hosts: ep.Name(),
			IP:    iface.Address().IP.String(),
		})

		recs = append(recs, etchosts.Record{
			Hosts: ep.Name() + "." + n.name,
			IP:    iface.Address().IP.String(),
		})
	}
	n.Unlock()

	// If there are no records to add or delete then simply return here
	if len(recs) == 0 {
		return
	}

	var sbList []*sandbox
	n.WalkEndpoints(func(e Endpoint) bool {
		if sb, hasSandbox := e.(*endpoint).getSandbox(); hasSandbox {
			sbList = append(sbList, sb)
		}
		return false
	})

	for _, sb := range sbList {
		if isAdd {
			sb.addHostsEntries(recs)
		} else {
			sb.deleteHostsEntries(recs)
		}
	}
}

func (n *network) getSvcRecords() []etchosts.Record {
	n.Lock()
	defer n.Unlock()

	var recs []etchosts.Record
	for h, ip := range n.svcRecords {
		recs = append(recs, etchosts.Record{
			Hosts: h,
			IP:    ip.String(),
		})
	}

	return recs
}

func (n *network) getController() *controller {
	n.Lock()
	defer n.Unlock()
	return n.ctrlr
}

func (n *network) ipamAllocate() ([]func(), error) {
	var (
		cnl []func()
		err error
	)

	// For now also exclude bridge from using new ipam
	if n.Type() == "host" || n.Type() == "null" || n.Type() == "bridge" {
		return cnl, nil
	}

	ipc, err := n.getController().getIPConfig(n.ipamType)
	if err != nil {
		return nil, err
	}

	ipa, err := n.getController().getIPAllocator(n.ipamType)
	if err != nil {
		return nil, err
	}

	// Lazily initialize empty config
	if len(n.ipamConfig) == 0 {
		as, err := n.deriveAddressSpace()
		if err != nil {
			return nil, err
		}
		n.ipamConfig = append(n.ipamConfig, IpamConf{AddressSpace: as})
	}

	for _, c := range n.ipamConfig {
		var (
			ip net.IP
			d  ipamInfo
		)

		if c.AddressSpace == "" {
			if c.AddressSpace, err = n.deriveAddressSpace(); err != nil {
				return nil, err
			}
		}

		d.poolID, d.Pool, d.Meta, err = ipc.RequestPool(c.AddressSpace, c.PreferredPool, c.SubPool, c.Options, c.IsV6)
		if err != nil {
			return nil, err
		}
		n.ipamInfo = append(n.ipamInfo, d)
		defer func() {
			if err != nil {
				if err := ipc.ReleasePool(d.poolID); err != nil {
					log.Warnf("Failed to release address pool %s after failure to create network %s (%s)", d.poolID, n.Name(), n.ID())
				}
			}
		}()

		// Reserve the gateway address if asked to do so
		if c.ReserveGateway {
			if gw, ok := c.Options[ipamapi.DefaultGateway]; ok {
				ip = net.ParseIP(gw)
			}
			d.gateway, _, err = ipa.RequestAddress(d.poolID, ip, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to allocate default gateway: %v", err)
			}
			cnl = append(cnl, func() {
				if err := ipa.ReleaseAddress(d.poolID, ip); err != nil {
					log.Warnf("Failed to release gw address %s after failure to create network %s (%s)", ip, n.Name(), n.ID())
				}
			})
		}
	}

	return cnl, nil
}

func (n *network) ipamRelease() {
	// For now also exclude bridge from using new ipam
	if n.Type() == "host" || n.Type() == "null" || n.Type() == "bridge" {
		return
	}
	ipc, err := n.getController().getIPConfig(n.ipamType)
	if err != nil {
		log.Warnf("Failed to retrieve ip config to release address pool(s) on delete of network %s (%s): %v", n.Name(), n.ID(), err)
	}
	for _, d := range n.ipamInfo {
		if ipc.ReleasePool(d.poolID); err != nil {
			log.Warnf("Failed to release address pool %s on delete of network %s (%s): %v", d.poolID, n.Name(), n.ID(), err)
		}
	}
}

func (n *network) getIPData() []ipamapi.IPData {
	l := make([]ipamapi.IPData, 0, len(n.ipamInfo))
	n.Lock()
	for _, d := range n.ipamInfo {
		l = append(l, d.IPData)
	}
	n.Unlock()
	return l
}

func (n *network) deriveAddressSpace() (string, error) {
	c := n.getController()
	c.Lock()
	ipc, ok := c.ipams[n.ipamType]
	c.Unlock()
	if !ok {
		return "", types.NotFoundErrorf("could not find ipam driver %s to get default address space", n.ipamType)
	}
	if n.isGlobalScoped() {
		return ipc.defaultGlobalAddressSpace, nil
	}
	return ipc.defaultLocalAddressSpace, nil
}
