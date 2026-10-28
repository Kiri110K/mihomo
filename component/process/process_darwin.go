package process

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

const (
	procpidpathinfo      = 0xb
	procpidpathinfosize  = 1024
	proccallnumlistpids  = 0x1
	proccallnumpidinfo   = 0x2
	proccallnumpidfdinfo = 0x3

	procallpids         = 0x1 // PROC_ALL_PIDS
	procpidlistfds      = 0x1 // PROC_PIDLISTFDS
	procpidfdsocketinfo = 0x3 // PROC_PIDFDSOCKETINFO
	proxfdtypesocket    = 0x2 // PROX_FDTYPE_SOCKET
	sockinfoin          = 0x1 // SOCKINFO_IN
	sockinfotcp         = 0x2 // SOCKINFO_TCP

	// from sys/proc_info.h, same on arm64 and amd64
	procfdinfosize      = 8   // sizeof(struct proc_fdinfo)
	socketfdinfosize    = 792 // sizeof(struct socket_fdinfo)
	soiprotocoloffset   = 180 // socket_fdinfo.psi.soi_protocol
	soikindoffset       = 256 // socket_fdinfo.psi.soi_kind
	insockinfooffset    = 264 // socket_fdinfo.psi.soi_proto.pri_in (pri_tcp.tcpsi_ini)
	insockinfominlen    = 64  // in_sockinfo up to the end of insi_laddr
	insockinfolport     = 4   // in_sockinfo.insi_lport
	insockinfovflag     = 24  // in_sockinfo.insi_vflag
	insockinfoladdr     = 48  // in_sockinfo.insi_laddr
	insockinfoladdr4pad = 12  // in4in6_addr.i46a_addr4 within insi_laddr
)

var structSize = func() int {
	value, _ := syscall.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(value, ".")
	n, _ := strconv.ParseInt(major, 10, 64)
	switch true {
	case n >= 22:
		return 408
	default:
		// from darwin-xnu/bsd/netinet/in_pcblist.c:get_pcblist_n
		// size/offset are round up (aligned) to 8 bytes in darwin
		// rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) +
		// 2 * rup8(sizeof(xsockbuf_n)) + rup8(sizeof(xsockstat_n))
		return 384
	}
}()

// readPCBList is replaced in tests to simulate a restricted kernel.
var readPCBList = func(name string) ([]byte, error) {
	return unix.SysctlRaw(name)
}

var restrictedPCBListOnce sync.Once

func findProcessName(network string, ip netip.Addr, port int) (uint32, string, error) {
	var spath string
	switch network {
	case TCP:
		spath = "net.inet.tcp.pcblist_n"
	case UDP:
		spath = "net.inet.udp.pcblist_n"
	default:
		return 0, "", ErrInvalidNetwork
	}

	path, restricted, err := findProcessNameByPCBList(spath, network, ip, port)
	if !restricted {
		return 0, path, err
	}

	// Since macOS 27 the kernel gives some processes not signed by Apple only their
	// own entries from pcblist_n (on 27.2, when not root: ad-hoc binaries whose code
	// signing identifier has no dot, e.g. "mihomo", and any process with an ad-hoc
	// ancestor). Look through the socket descriptors of other processes instead,
	// the way lsof does.
	path, err = findProcessBySocketScan(network, ip, port)
	return 0, path, err
}

// findProcessNameByPCBList looks the socket up in the kernel's pcblist_n table.
// restricted reports a table that holds no socket of any other process although
// its header counts more sockets than it holds.
func findProcessNameByPCBList(spath string, network string, ip netip.Addr, port int) (path string, restricted bool, err error) {
	isIPv4 := ip.Is4()

	value, err := readPCBList(spath)
	if err != nil {
		return "", false, err
	}

	buf := value
	itemSize := structSize
	if network == TCP {
		// rup8(sizeof(xtcpcb_n))
		itemSize += 208
	}

	var (
		fallbackUDPProcess string
		records            int
		foreignRecords     int
		selfPID            = uint32(os.Getpid())
	)
	// skip the first xinpgen(24 bytes) block
	for i := 24; i+itemSize <= len(buf); i += itemSize {
		// offset of xinpcb_n and xsocket_n
		inp, so := i, i+104

		records++
		if readNativeUint32(buf[so+68:so+72]) != selfPID {
			foreignRecords++
		}

		srcPort := binary.BigEndian.Uint16(buf[inp+18 : inp+20])
		if uint16(port) != srcPort {
			continue
		}

		// xinpcb_n.inp_vflag
		flag := buf[inp+44]

		var (
			srcIP     netip.Addr
			srcIsIPv4 bool
		)
		switch {
		case flag&0x1 > 0 && isIPv4:
			// ipv4
			srcIP, _ = netip.AddrFromSlice(buf[inp+76 : inp+80])
			srcIsIPv4 = true
		case flag&0x2 > 0 && !isIPv4:
			// ipv6
			srcIP, _ = netip.AddrFromSlice(buf[inp+64 : inp+80])
		default:
			continue
		}
		srcIP = srcIP.Unmap()

		if ip == srcIP {
			// xsocket_n.so_last_pid
			pid := readNativeUint32(buf[so+68 : so+72])
			pp, err := getExecPathFromPID(pid)
			return pp, false, err
		}

		// udp packet connection may be not equal with srcIP
		if network == UDP && srcIP.IsUnspecified() && isIPv4 == srcIsIPv4 {
			fallbackUDPProcess, _ = getExecPathFromPID(readNativeUint32(buf[so+68 : so+72]))
		}
	}

	if network == UDP && fallbackUDPProcess != "" {
		return fallbackUDPProcess, false, nil
	}

	var expected uint32
	if len(buf) >= 8 {
		// xinpgen.xig_count
		expected = readNativeUint32(buf[4:8])
	}
	if foreignRecords == 0 && int(expected) > records {
		restrictedPCBListOnce.Do(func() {
			log.Warnln("[Process] kernel returned only this process's sockets from %s (%d records, header counts %d), as macOS 27+ does for some binaries not signed by Apple; falling back to a per-process socket scan", spath, records, expected)
			if os.Geteuid() != 0 {
				log.Warnln("[Process] not running as root: sockets of other users' processes cannot be matched")
			}
		})
		return "", true, ErrNotFound
	}

	return "", false, ErrNotFound
}

// recentSocketOwners holds the pids that matched last, which are scanned first:
// most connections come from a few processes such as a browser's network service.
var recentSocketOwners struct {
	sync.Mutex
	pids [8]uint32
	next int
}

func rememberSocketOwner(pid uint32) {
	recentSocketOwners.Lock()
	defer recentSocketOwners.Unlock()
	for _, p := range recentSocketOwners.pids {
		if p == pid {
			return
		}
	}
	recentSocketOwners.pids[recentSocketOwners.next] = pid
	recentSocketOwners.next = (recentSocketOwners.next + 1) % len(recentSocketOwners.pids)
}

// findProcessBySocketScan walks the socket descriptors of every process the way
// lsof does: proc_listpids, then PROC_PIDLISTFDS and PROC_PIDFDSOCKETINFO per pid.
// Like the pcblist lookup it matches the local address only. A socket held by
// several processes (e.g. inherited across fork) is reported for the first holder
// found, recent owners first, while pcblist reports the last process that used it.
func findProcessBySocketScan(network string, ip netip.Addr, port int) (string, error) {
	recentSocketOwners.Lock()
	recent := recentSocketOwners.pids
	recentSocketOwners.Unlock()

	s := socketScanner{
		network: network,
		ip:      ip,
		port:    uint16(port),
		fds:     make([]byte, 256*procfdinfosize),
		// larger than socket_fdinfo in case it grows
		info: make([]byte, 2*socketfdinfosize),
	}
	selfPID := uint32(os.Getpid())

	for _, pid := range recent {
		if pid != 0 && s.scan(pid) {
			return getExecPathFromPID(pid)
		}
	}
	// a recent owner of a udp socket bound to 0.0.0.0 is taken without walking
	// every process: an exact match elsewhere on the same port needs port reuse
	if s.fallbackUDPPID != 0 {
		return getExecPathFromPID(s.fallbackUDPPID)
	}

	pids, err := listAllPIDs()
	if err != nil {
		return "", err
	}
	for _, pid := range pids {
		if pid == 0 || pid == selfPID {
			continue
		}
		if containsPID(recent[:], pid) {
			continue
		}
		if s.scan(pid) {
			rememberSocketOwner(pid)
			return getExecPathFromPID(pid)
		}
	}

	if s.fallbackUDPPID != 0 {
		rememberSocketOwner(s.fallbackUDPPID)
		return getExecPathFromPID(s.fallbackUDPPID)
	}

	return "", ErrNotFound
}

type socketScanner struct {
	network        string
	ip             netip.Addr
	port           uint16
	fds            []byte
	info           []byte
	fallbackUDPPID uint32
}

// scan reports whether pid holds a socket bound to the address being looked up.
func (s *socketScanner) scan(pid uint32) bool {
	n, err := procInfo(proccallnumpidinfo, pid, procpidlistfds, 0, s.fds)
	if err != nil {
		// EPERM for processes of other users when not running as root,
		// ESRCH for processes that have exited since listing
		return false
	}
	// a full buffer may have cut the list short: ask for its size and retry,
	// with room for descriptors opened in between
	for retry := 0; n >= len(s.fds) && retry < 3; retry++ {
		need, err := procInfo(proccallnumpidinfo, pid, procpidlistfds, 0, nil)
		if err != nil {
			return false
		}
		if need < len(s.fds) {
			need = len(s.fds)
		}
		s.fds = make([]byte, need+64*procfdinfosize)
		if n, err = procInfo(proccallnumpidinfo, pid, procpidlistfds, 0, s.fds); err != nil {
			return false
		}
	}

	wantProto := uint32(syscall.IPPROTO_TCP)
	if s.network == UDP {
		wantProto = syscall.IPPROTO_UDP
	}
	isIPv4 := s.ip.Is4()

	for i := 0; i+procfdinfosize <= n; i += procfdinfosize {
		// proc_fdinfo.proc_fdtype
		if readNativeUint32(s.fds[i+4:i+8]) != proxfdtypesocket {
			continue
		}
		// proc_fdinfo.proc_fd
		fd := readNativeUint32(s.fds[i : i+4])

		m, err := procInfo(proccallnumpidfdinfo, pid, procpidfdsocketinfo, uint64(fd), s.info)
		if err != nil || m < insockinfooffset+insockinfominlen {
			continue
		}

		kind := readNativeUint32(s.info[soikindoffset : soikindoffset+4])
		if kind != sockinfoin && kind != sockinfotcp {
			continue
		}
		if readNativeUint32(s.info[soiprotocoloffset:soiprotocoloffset+4]) != wantProto {
			continue
		}

		in := s.info[insockinfooffset:]
		// in_sockinfo.insi_lport holds the port in network byte order
		if binary.BigEndian.Uint16(in[insockinfolport:insockinfolport+2]) != s.port {
			continue
		}

		flag := in[insockinfovflag]
		laddr := in[insockinfoladdr : insockinfoladdr+16]

		var (
			srcIP     netip.Addr
			srcIsIPv4 bool
		)
		switch {
		case flag&0x1 > 0 && isIPv4:
			// ipv4
			srcIP, _ = netip.AddrFromSlice(laddr[insockinfoladdr4pad:16])
			srcIsIPv4 = true
		case flag&0x2 > 0 && !isIPv4:
			// ipv6
			srcIP, _ = netip.AddrFromSlice(laddr)
		default:
			continue
		}
		srcIP = srcIP.Unmap()

		if s.ip == srcIP {
			return true
		}

		// udp packet connection may be not equal with srcIP
		if s.network == UDP && srcIP.IsUnspecified() && isIPv4 == srcIsIPv4 {
			s.fallbackUDPPID = pid
		}
	}

	return false
}

func listAllPIDs() ([]uint32, error) {
	need, err := procInfo(proccallnumlistpids, procallpids, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	// leave room for processes started in between
	buf := make([]byte, need+256*4)
	n, err := procInfo(proccallnumlistpids, procallpids, 0, 0, buf)
	if err != nil {
		return nil, err
	}
	pids := make([]uint32, 0, n/4)
	for i := 0; i+4 <= n; i += 4 {
		pids = append(pids, readNativeUint32(buf[i:i+4]))
	}
	return pids, nil
}

func containsPID(pids []uint32, pid uint32) bool {
	for _, p := range pids {
		if p == pid {
			return true
		}
	}
	return false
}

// procInfo calls __proc_info(callnum, pid, flavor, arg, buf, len(buf)).
// With an empty buf the kernel returns the size it needs.
func procInfo(callnum int, pid uint32, flavor int, arg uint64, buf []byte) (int, error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	r1, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		uintptr(callnum),
		uintptr(pid),
		uintptr(flavor),
		uintptr(arg),
		uintptr(ptr),
		uintptr(len(buf)))
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

func getExecPathFromPID(pid uint32) (string, error) {
	buf := make([]byte, procpidpathinfosize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		proccallnumpidinfo,
		uintptr(pid),
		procpidpathinfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procpidpathinfosize)
	if errno != 0 {
		return "", errno
	}

	return unix.ByteSliceToString(buf), nil
}

func readNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
