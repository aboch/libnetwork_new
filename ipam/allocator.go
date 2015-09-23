package ipam

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/docker/libkv/store"
	"github.com/docker/libnetwork/bitseq"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/types"
)

const (
	localAddressSpace  = "LocalDefault"
	globalAddressSpace = "GlobalDefault"
	// The biggest configurable host subnets
	minNetSize      = 8
	minNetSizeV6    = 64
	minNetSizeV6Eff = 96
	// datastore keyes for ipam objects
	dsConfigKey = "ipam/" + ipamapi.DefaultIPAM + "/config"
	dsDataKey   = "ipam/" + ipamapi.DefaultIPAM + "/data"
)

var (
	localPredefinedPools  []*net.IPNet
	globalPredefinedPools []*net.IPNet
)

func init() {
	localPredefinedPools = initLocalPredefinedPools()
	globalPredefinedPools = initGlobalPredefinedPools()
}

type addressRange struct {
	start, end uint32
}

func (r *addressRange) String() string {
	return fmt.Sprintf("[%d, %d]", r.start, r.end)
}

// PoolData contains the configured pool data
type PoolData struct {
	ParentKey subnetKey
	Pool      *net.IPNet
	Range     *addressRange
	RefCount  uint32
}

func (p *PoolData) String() string {
	return fmt.Sprintf("ParentKey: %s, Pool: %s, Range: %s, RefCount: %d",
		p.ParentKey.String(), p.Pool.String(), p.Range, p.RefCount)
}

// Allocator provides per address space ipv4/ipv6 book keeping
type Allocator struct {
	// Predefined pools for default address spaces
	predefined map[string][]*net.IPNet
	// Static subnet information
	subnets map[subnetKey]*PoolData
	// Allocated addresses in each address space's subnet
	addresses map[subnetKey]*bitseq.Handle
	// Datastore
	store    datastore.DataStore
	dbIndex  uint64
	dbExists bool
	sync.Mutex
}

// NewAllocator returns an instance of libnetwork ipam
func NewAllocator(ds datastore.DataStore) (*Allocator, error) {
	a := &Allocator{}
	a.subnets = make(map[subnetKey]*PoolData)
	a.addresses = make(map[subnetKey]*bitseq.Handle)
	a.predefined = make(map[string][]*net.IPNet, 2)
	a.predefined[localAddressSpace] = localPredefinedPools
	a.predefined[globalAddressSpace] = globalPredefinedPools
	a.store = ds

	if a.store == nil {
		return a, nil
	}

	// Register for status changes
	a.watchForChanges()

	// Get the initial subnet configs status from the ds if present.
	kvPair, err := a.store.KVStore().Get(datastore.Key(a.Key()...))
	if err != nil {
		if err != store.ErrKeyNotFound {
			return nil, fmt.Errorf("failed to retrieve the ipam subnet configs from datastore: %v", err)
		}
		return a, nil
	}
	a.subnetConfigFromStore(kvPair)

	// Now retrieve the bitmasks for the parent pools
	var inserterList []func() error
	a.Lock()
	for k, v := range a.subnets {
		if v.Range == nil {
			inserterList = append(inserterList, func() error { return a.insertBitMask(k, v.Pool) })
		}
	}
	a.Unlock()

	// Add the bitmasks, data could come from datastore
	for _, f := range inserterList {
		if err := f(); err != nil {
			return nil, err
		}
	}

	return a, nil
}

func (a *Allocator) subnetConfigFromStore(kvPair *store.KVPair) {
	a.Lock()
	if a.dbIndex < kvPair.LastIndex {
		a.subnets = byteArrayToSubnets(kvPair.Value)
		a.dbIndex = kvPair.LastIndex
		a.dbExists = true
	}
	a.Unlock()
}

// Pointer to the configured subnets in each address space
type subnetKey struct {
	addressSpace string
	subnet       string
	childSubnet  string
}

func (s *subnetKey) String() string {
	k := fmt.Sprintf("%s/%s", s.addressSpace, s.subnet)
	if s.childSubnet != "" {
		k = fmt.Sprintf("%s/%s", k, s.childSubnet)
	}
	return k
}

func (s *subnetKey) FromString(str string) error {
	if str == "" || !strings.Contains(str, "/") {
		return fmt.Errorf("invalid string form for subnetkey: %s", str)
	}

	p := strings.Split(str, "/")
	if len(p) != 3 && len(p) != 5 {
		return fmt.Errorf("invalid string form for subnetkey: %s", str)
	}
	s.addressSpace = p[0]
	s.subnet = fmt.Sprintf("%s/%s", p[1], p[2])
	if len(p) == 5 {
		s.childSubnet = fmt.Sprintf("%s/%s", p[3], p[4])
	}

	return nil
}

func (s *subnetKey) canonicalSubnet() *net.IPNet {
	if _, sub, err := net.ParseCIDR(s.subnet); err == nil {
		return sub
	}
	return nil
}

func (s *subnetKey) canonicalChildSubnet() *net.IPNet {
	if _, sub, err := net.ParseCIDR(s.childSubnet); err == nil {
		return sub
	}
	return nil
}

type ipVersion int

const (
	v4 = 4
	v6 = 6
)

/******************
 * Config Contract
 ******************/

// GetDefaultAddressSpaces returns the local and global default address spaces
func (a *Allocator) GetDefaultAddressSpaces() (string, string, error) {
	return localAddressSpace, globalAddressSpace, nil
}

// RequestPool returns an address pool along with its unique id.
func (a *Allocator) RequestPool(addressSpace, pool, subPool string, options map[string]string, v6 bool) (string, *net.IPNet, map[string]string, error) {
	var (
		nw, pw   *net.IPNet
		ipr      *addressRange
		c, p, pp *PoolData
		ok       bool
		err      error
	)

	if addressSpace == "" {
		return "", nil, nil, ipamapi.ErrInvalidAddressSpace
	}

	if pool == "" && subPool != "" {
		return "", nil, nil, ipamapi.ErrInvalidSubPool
	}

	if pool != "" {
		_, nw, err = net.ParseCIDR(pool)
		if err != nil {
			return "", nil, nil, ipamapi.ErrInvalidPool
		}
		if pw, err = adjustAndCheckSubnetSize(nw); err != nil {
			return "", nil, nil, err
		}
		// Reset pool to canonical form
		pool = types.GetIPNetCanonical(nw).String()
		if subPool != "" {
			ipr, err = getAddressRange(subPool)
			if err != nil {
				return "", nil, nil, err
			}
		}
	} else {
		pool, nw, err = a.getPredefinedPool(addressSpace, v6)
		if err != nil {
			return "", nil, nil, err
		}
		if pw, err = adjustAndCheckSubnetSize(nw); err != nil {
			return "", nil, nil, err
		}
	}

	k := subnetKey{addressSpace: addressSpace, subnet: pool, childSubnet: subPool}

retry:
	if ipr == nil {
		a.Lock()
		if p, ok = a.subnets[k]; ok {
			p.RefCount++
			goto finalize
		}
		a.Unlock()
		if a.contains(addressSpace, nw) {
			return "", nil, nil, ipamapi.ErrPoolOverlap
		}
	}

	a.Lock()
	if p, ok = a.subnets[k]; ok {
		c = p
		for ok {
			c.RefCount++
			c, ok = a.subnets[c.ParentKey]
		}
		goto finalize
	}

	p = &PoolData{
		Pool:     pw,
		Range:    ipr,
		RefCount: 1,
	}

	if p.Range == nil {
		a.Unlock()
		if err := a.insertBitMask(k, p.Pool); err != nil {
			return "", nil, nil, err
		}
		a.Lock()
		a.subnets[k] = p
		goto finalize
	}

	p.ParentKey = subnetKey{addressSpace: addressSpace, subnet: pool}
	a.subnets[k] = p
	if pp, ok = a.subnets[p.ParentKey]; ok {
		c = pp
		for ok {
			c.RefCount++
			c, ok = a.subnets[c.ParentKey]
		}
		goto finalize
	}

	a.Unlock()

	// parent does not exist
	pp = &PoolData{
		Pool:     p.Pool,
		RefCount: 1,
	}
	if err := a.insertBitMask(p.ParentKey, pp.Pool); err != nil {
		return "", nil, nil, err
	}

	a.Lock()
	a.subnets[p.ParentKey] = pp
finalize:
	a.Unlock()
	err = a.writeToStore()
	if err != nil {
		if _, ok := err.(types.RetryError); !ok {
			return "", nil, nil, types.InternalErrorf("pool configuration failed because of %s", err.Error())
		}
		// Update to latest
		if erru := a.readFromStore(); erru != nil {
			return "", nil, nil, fmt.Errorf("failed to get updated pool config from datastore (%v) after (%v)", erru, err)
		}
		goto retry
	}

	return k.String(), p.Pool, nil, nil
}

func (a *Allocator) insertBitMask(key subnetKey, pool *net.IPNet) error {
	ipVer := getAddressVersion(pool.IP)
	ones, bits := pool.Mask.Size()
	numAddresses := uint32(1 << uint(bits-ones))

	if ipVer == v4 {
		// Do not let broadcast address be reserved
		numAddresses--
	}

	// Generate the new address masks. AddressMask content may come from datastore
	h, err := bitseq.NewHandle(dsDataKey, a.store, key.String(), numAddresses)
	if err != nil {
		return err
	}

	if ipVer == v4 {
		// Do not let network identifier address be reserved
		h.Set(0)
	}

	a.Lock()
	a.addresses[key] = h
	a.Unlock()

	return nil
}

// ReleasePool releases the address pool identified by the passed id
func (a *Allocator) ReleasePool(poolID string) error {
	var (
		p, pp *PoolData
		rk    *subnetKey
		ok    bool
	)
	k := subnetKey{}
	if err := k.FromString(poolID); err != nil {
		return types.BadRequestErrorf("invalid pool id: %s", poolID)
	}

retry:
	a.Lock()
	p, ok = a.subnets[k]
	if !ok {
		a.Unlock()
		return ipamapi.ErrBadPool
	}
	p.RefCount--
	if p.RefCount == 0 {
		delete(a.subnets, k)
		rk = &k
	}

	if p.Range != nil {
		pp, ok = a.subnets[p.ParentKey]
		if !ok {
			a.Unlock()
			return types.InternalErrorf("cannot find parent pool for %s", poolID)
		}
		pp.RefCount--
		if pp.RefCount == 0 {
			delete(a.subnets, p.ParentKey)
			rk = &p.ParentKey
		}
		a.Unlock()
		return nil
	}
	a.Unlock()
	if err := a.writeToStore(); err != nil {
		if _, ok := err.(types.RetryError); !ok {
			return types.InternalErrorf("pool (%s) removal failed because of %v", poolID, err)
		}
		// Update to latest
		if erru := a.readFromStore(); erru != nil {
			return fmt.Errorf("failed to get updated pool config from datastore (%v) after (%v)", erru, err)
		}
		goto retry
	}

	if rk == nil {
		return nil
	}

	a.Lock()
	if bm, ok := a.addresses[*rk]; ok {
		bm.Destroy()
	}
	delete(a.addresses, *rk)
	a.Unlock()

	return nil
}

func (a *Allocator) getPredefineds(as string) []*net.IPNet {
	a.Lock()
	defer a.Unlock()
	l := make([]*net.IPNet, 0, len(a.predefined[as]))
	for _, pool := range a.predefined[as] {
		l = append(l, pool)
	}
	return l
}

func (a *Allocator) getPredefinedPool(as string, ipV6 bool) (string, *net.IPNet, error) {
	var v ipVersion
	v = v4
	if ipV6 {
		v = v6
	}

	if as != localAddressSpace && as != globalAddressSpace {
		return "", nil, fmt.Errorf("no default pool availbale for non-default addresss spaces")
	}

	for _, nw := range a.getPredefineds(as) {
		if v != getAddressVersion(nw.IP) {
			continue
		}
		cw := types.GetIPNetCanonical(nw)
		if _, ok := a.subnets[subnetKey{addressSpace: as, subnet: cw.String()}]; ok {
			continue
		}
		if !a.contains(as, cw) {
			if as == localAddressSpace {
				if err := netutils.CheckRouteOverlaps(nw); err == nil {
					return cw.String(), nw, nil
				}
				continue
			}
			return cw.String(), nw, nil
		}
	}

	return "", nil, types.NotFoundErrorf("could not find an available predefined network")
}

// Check subnets size. In case configured subnet is v6 and host size is
// greater than 32 bits, adjust subnet to /96.
func adjustAndCheckSubnetSize(subnet *net.IPNet) (*net.IPNet, error) {
	ones, bits := subnet.Mask.Size()
	if v6 == getAddressVersion(subnet.IP) {
		if ones < minNetSizeV6 {
			return nil, ipamapi.ErrInvalidPool
		}
		if ones < minNetSizeV6Eff {
			newMask := net.CIDRMask(minNetSizeV6Eff, bits)
			return &net.IPNet{IP: subnet.IP, Mask: newMask}, nil
		}
	} else {
		if ones < minNetSize {
			return nil, ipamapi.ErrInvalidPool
		}
	}
	return subnet, nil
}

// Checks whether the passed subnet is a superset or subset of any of the subset in the db
func (a *Allocator) contains(space string, nw *net.IPNet) bool {
	a.Lock()
	defer a.Unlock()
	for k, v := range a.subnets {
		if space == k.addressSpace && k.childSubnet == "" {
			if nw.Contains(v.Pool.IP) || v.Pool.Contains(nw.IP) {
				return true
			}
		}
	}
	return false
}

/*********************
 * Allocator Contract
 *********************/

// RequestAddress returns an address from the specified pool ID
func (a *Allocator) RequestAddress(poolID string, prefAddress net.IP, opts map[string]string) (*net.IPNet, map[string]string, error) {
	k := subnetKey{}
	if err := k.FromString(poolID); err != nil {
		return nil, nil, types.BadRequestErrorf("invalid pool id: %s", poolID)
	}

	a.Lock()
	defer a.Unlock()
	p, ok := a.subnets[k]
	if !ok {
		return nil, nil, types.NotFoundErrorf("cannot find address pool for poolID:%s", poolID)
	}

	if prefAddress != nil && !p.Pool.Contains(prefAddress) {
		return nil, nil, ipamapi.ErrIPOutOfRange
	}

	c := p
	for c.Range != nil {
		k = c.ParentKey
		c, ok = a.subnets[k]
	}

	ip, err := a.getAddress(c.Pool, a.addresses[k], prefAddress, p.Range)
	if err != nil {
		return nil, nil, err
	}

	return &net.IPNet{IP: ip, Mask: p.Pool.Mask}, nil, nil
}

// ReleaseAddress releases the address from the specified pool ID
func (a *Allocator) ReleaseAddress(poolID string, address net.IP) error {
	k := subnetKey{}
	if err := k.FromString(poolID); err != nil {
		return types.BadRequestErrorf("invalid pool id: %s", poolID)
	}

	a.Lock()
	defer a.Unlock()
	p, ok := a.subnets[k]
	if !ok {
		return ipamapi.ErrBadPool
	}

	if address == nil || !p.Pool.Contains(address) {
		return ipamapi.ErrInvalidRequest
	}

	c := p
	for c.Range != nil {
		k = c.ParentKey
		c = a.subnets[k]
	}

	bm, ok := a.addresses[k]
	if !ok {
		return fmt.Errorf("failed to locate bitmask")
	}

	h, err := types.GetHostPartIP(address, c.Pool.Mask)
	if err != nil {
		return fmt.Errorf("failed to release address %s: %v", address.String(), err)
	}

	return bm.Unset(ipToUint32(h))
}

func (a *Allocator) getAddress(subnet *net.IPNet, bitmask *bitseq.Handle, prefAddress net.IP, ipr *addressRange) (net.IP, error) {
	var (
		ordinal uint32
		err     error
	)

	if bitmask.Unselected() <= 0 {
		return nil, ipamapi.ErrNoAvailableIPs
	}
	if ipr == nil && prefAddress == nil {
		ordinal, err = bitmask.SetAny()
	} else if ipr != nil {
		ordinal, err = bitmask.SetAnyInRange(ipr.start, ipr.end)
	} else {
		hostPart, e := types.GetHostPartIP(prefAddress, subnet.Mask)
		if e != nil {
			return nil, fmt.Errorf("failed to allocate preferred address %s: %v", prefAddress.String(), e)
		}
		ordinal = ipToUint32(types.GetMinimalIP(hostPart))
		err = bitmask.Set(ordinal)
	}
	if err != nil {
		return nil, ipamapi.ErrNoAvailableIPs
	}

	// Convert IP ordinal for this subnet into IP address
	return generateAddress(ordinal, subnet), nil
}

// DumpDatabase dumps the internal info
func (a *Allocator) DumpDatabase() {
	a.Lock()
	defer a.Unlock()

	fmt.Printf("\n\nPoolData")
	for k, config := range a.subnets {
		fmt.Printf("\n%v: %v", k, config)
	}

	fmt.Printf("\n\nBitmasks")
	for k, bm := range a.addresses {
		fmt.Printf("\n\t%s: %s\n\t%d", k, bm, bm.Unselected())
	}
}

// It generates the ip address in the passed subnet specified by
// the passed host address ordinal
func generateAddress(ordinal uint32, network *net.IPNet) net.IP {
	var address [16]byte

	// Get network portion of IP
	if getAddressVersion(network.IP) == v4 {
		copy(address[:], network.IP.To4())
	} else {
		copy(address[:], network.IP)
	}

	end := len(network.Mask)
	addIntToIP(address[:end], ordinal)

	return net.IP(address[:end])
}

func getAddressVersion(ip net.IP) ipVersion {
	if ip.To4() == nil {
		return v6
	}
	return v4
}

// Adds the ordinal IP to the current array
// 192.168.0.0 + 53 => 192.168.53
func addIntToIP(array []byte, ordinal uint32) {
	for i := len(array) - 1; i >= 0; i-- {
		array[i] |= (byte)(ordinal & 0xff)
		ordinal >>= 8
	}
}

// Convert an ordinal to the respective IP address
func ipToUint32(ip []byte) uint32 {
	value := uint32(0)
	for i := 0; i < len(ip); i++ {
		j := len(ip) - 1 - i
		value += uint32(ip[i]) << uint(j*8)
	}
	return value
}

func initLocalPredefinedPools() []*net.IPNet {
	pl := make([]*net.IPNet, 0, 274)
	mask := []byte{255, 255, 0, 0}
	for i := 17; i < 32; i++ {
		pl = append(pl, &net.IPNet{IP: []byte{172, byte(i), 42, 1}, Mask: mask})
	}
	// 10.[0-255].42.1/16
	for i := 0; i < 256; i++ {
		pl = append(pl, &net.IPNet{IP: []byte{10, byte(i), 42, 1}, Mask: mask})
	}
	// 192.168.[42-44].1/24
	mask24 := []byte{255, 255, 255, 0}
	for i := 42; i < 45; i++ {
		pl = append(pl, &net.IPNet{IP: []byte{192, 168, byte(i), 1}, Mask: mask24})
	}
	return pl
}

func initGlobalPredefinedPools() []*net.IPNet {
	pl := make([]*net.IPNet, 0, 256*256)
	mask := []byte{255, 255, 255, 0}
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			pl = append(pl, &net.IPNet{IP: []byte{10, byte(i), byte(j), 0}, Mask: mask})
		}
	}
	return pl
}

func getAddressRange(pool string) (*addressRange, error) {
	_, nw, err := net.ParseCIDR(pool)
	if err != nil {
		return nil, ipamapi.ErrInvalidSubPool
	}
	lIP, e := types.GetHostPartIP(nw.IP, nw.Mask)
	if e != nil {
		return nil, fmt.Errorf("failed to compute range's lowest ip address: %v", e)
	}
	bIP, e := types.GetBroadcastIP(nw.IP, nw.Mask)
	if e != nil {
		return nil, fmt.Errorf("failed to compute range's broadcast ip address: %v", e)
	}
	hIP, e := types.GetHostPartIP(bIP, nw.Mask)
	if e != nil {
		return nil, fmt.Errorf("failed to compute range's highest ip address: %v", e)
	}
	return &addressRange{ipToUint32(types.GetMinimalIP(lIP)), ipToUint32(types.GetMinimalIP(hIP))}, nil
}
