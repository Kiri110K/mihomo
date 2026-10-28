package process

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ncPath = "/usr/bin/nc"

// peerEnv makes the test binary act as a peer, see runPeer.
const peerEnv = "MIHOMO_PROCESS_TEST_PEER"

// peerTimeout bounds every wait for a peer, so a peer that failed to start
// fails the test instead of hanging it.
const peerTimeout = 10 * time.Second

func TestMain(m *testing.M) {
	if mode, addr, ok := strings.Cut(os.Getenv(peerEnv), " "); ok {
		if err := runPeer(mode, addr); err != nil {
			fmt.Fprintln(os.Stderr, "peer:", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runPeer connects or sends to addr, then keeps its socket open until stdin closes.
//
//	manyfds:     a TCP connection behind 400 other descriptors, more than the
//	             first PROC_PIDLISTFDS buffer takes
//	udpwildcard: a UDP datagram from a socket bound to 0.0.0.0
func runPeer(mode, addr string) error {
	switch mode {
	case "manyfds":
		null, err := os.Open(os.DevNull)
		if err != nil {
			return err
		}
		for fd := 100; fd < 500; fd++ {
			if err := syscall.Dup2(int(null.Fd()), fd); err != nil {
				return err
			}
		}
		conn, err := net.Dial("tcp4", addr)
		if err != nil {
			return err
		}
		f, err := conn.(*net.TCPConn).File()
		if err != nil {
			return err
		}
		if err := syscall.Dup2(int(f.Fd()), 600); err != nil {
			return err
		}
		_ = f.Close()
		_ = conn.Close()
	case "udpwildcard":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return err
		}
		// keeps conn reachable, or its finalizer may close the socket
		defer conn.Close()
		to, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo([]byte("ping"), to); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	_, err := io.Copy(io.Discard, os.Stdin)
	return err
}

// startSelfPeer runs this test binary as a peer and returns its path as
// proc_pidpath reports it.
func startSelfPeer(t *testing.T, mode, addr string) string {
	self, err := os.Executable()
	require.NoError(t, err)
	// proc_pidpath reports /private/var for /var
	self, err = filepath.EvalSymlinks(self)
	require.NoError(t, err)
	start(t, exec.Command(self), peerEnv+"="+mode+" "+addr)
	return self
}

// start runs cmd and keeps it, and its socket, alive until the test ends.
func start(t *testing.T, cmd *exec.Cmd, env ...string) io.Writer {
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return stdin
}

// simulateOwnSocketsOnly makes pcblist_n behave as on macOS 27 for binaries not
// signed by Apple: the xinpgen header and trailer stay, but only the records of
// sockets owned by this process are left in between.
func simulateOwnSocketsOnly(t *testing.T) {
	orig := readPCBList
	t.Cleanup(func() { readPCBList = orig })
	readPCBList = func(name string) ([]byte, error) {
		buf, err := orig(name)
		if err != nil {
			return nil, err
		}
		itemSize := structSize
		if name == "net.inet.tcp.pcblist_n" {
			itemSize += 208
		}
		self := uint32(os.Getpid())
		out := append([]byte(nil), buf[:24]...)
		i := 24
		for ; i+itemSize <= len(buf); i += itemSize {
			if readNativeUint32(buf[i+104+68:]) == self {
				out = append(out, buf[i:i+itemSize]...)
			}
		}
		return append(out, buf[i:]...), nil
	}
}

func loopback(network string) string {
	if strings.HasSuffix(network, "6") {
		return "::1"
	}
	return "127.0.0.1"
}

// tcpPeer accepts the connection that start makes to a listener on network and
// returns its source address.
func tcpPeer(t *testing.T, network string, start func(addr string)) netip.AddrPort {
	ln, err := net.ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(loopback(network))})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	require.NoError(t, ln.SetDeadline(time.Now().Add(peerTimeout)))

	start(ln.Addr().String())

	conn, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn.RemoteAddr().(*net.TCPAddr).AddrPort()
}

// udpPeer returns the source address of the datagram that start sends to a
// socket on network.
func udpPeer(t *testing.T, network string, start func(addr string)) netip.AddrPort {
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(loopback(network))})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(peerTimeout)))

	start(conn.LocalAddr().String())

	buf := make([]byte, 64)
	_, from, err := conn.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	return from
}

func ncArgs(network, addr string, udp bool) []string {
	host, port, _ := net.SplitHostPort(addr)
	args := []string{"-n", host, port}
	if udp {
		args = append([]string{"-u"}, args...)
	}
	if strings.HasSuffix(network, "6") {
		args = append([]string{"-6"}, args...)
	}
	return args
}

func ncTCP(t *testing.T, network string) (netip.AddrPort, string) {
	return tcpPeer(t, network, func(addr string) {
		start(t, exec.Command(ncPath, ncArgs(network, addr, false)...))
	}), ncPath
}

func ncUDP(t *testing.T, network string) (netip.AddrPort, string) {
	return udpPeer(t, network, func(addr string) {
		stdin := start(t, exec.Command(ncPath, ncArgs(network, addr, true)...))
		_, err := stdin.Write([]byte("ping\n"))
		require.NoError(t, err)
	}), ncPath
}

func TestFindProcessName(t *testing.T) {
	cases := []struct {
		name    string
		network string
		peer    func(t *testing.T) (netip.AddrPort, string)
	}{
		{"tcp4", TCP, func(t *testing.T) (netip.AddrPort, string) { return ncTCP(t, "tcp4") }},
		{"tcp6", TCP, func(t *testing.T) (netip.AddrPort, string) { return ncTCP(t, "tcp6") }},
		{"udp4", UDP, func(t *testing.T) (netip.AddrPort, string) { return ncUDP(t, "udp4") }},
		{"udp6", UDP, func(t *testing.T) (netip.AddrPort, string) { return ncUDP(t, "udp6") }},
		{"udp4 bound to 0.0.0.0", UDP, func(t *testing.T) (netip.AddrPort, string) {
			var self string
			src := udpPeer(t, "udp4", func(addr string) { self = startSelfPeer(t, "udpwildcard", addr) })
			return src, self
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, want := c.peer(t)
			ip, port := src.Addr().Unmap(), int(src.Port())

			t.Run("pcblist", func(t *testing.T) {
				_, path, err := findProcessName(c.network, ip, port)
				require.NoError(t, err)
				assert.Equal(t, want, path)
			})

			t.Run("socket scan", func(t *testing.T) {
				path, err := findProcessBySocketScan(c.network, ip, port)
				require.NoError(t, err)
				assert.Equal(t, want, path)
			})

			t.Run("restricted pcblist", func(t *testing.T) {
				simulateOwnSocketsOnly(t)

				// what mihomo did before: nothing found (MetaCubeX/mihomo#3355)
				spath := "net.inet." + c.network + ".pcblist_n"
				_, restricted, err := findProcessNameByPCBList(spath, c.network, ip, port)
				assert.ErrorIs(t, err, ErrNotFound)
				assert.True(t, restricted)

				_, path, err := findProcessName(c.network, ip, port)
				require.NoError(t, err)
				assert.Equal(t, want, path)
			})
		})
	}
}

// PROC_PIDLISTFDS stops when the buffer is full, so a socket behind hundreds of
// other descriptors is only found once the scan retries with a larger buffer.
func TestFindProcessBySocketScanManyFDs(t *testing.T) {
	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))
	if limit.Max < 1024 {
		t.Skipf("the peer needs descriptor 600, RLIMIT_NOFILE hard limit is %d", limit.Max)
	}

	var self string
	src := tcpPeer(t, "tcp4", func(addr string) { self = startSelfPeer(t, "manyfds", addr) })

	path, err := findProcessBySocketScan(TCP, src.Addr().Unmap(), int(src.Port()))
	require.NoError(t, err)
	assert.Equal(t, self, path)
}

// A table that holds only our own sockets is not restricted when its header
// does not count more.
func TestFindProcessNameByPCBListOwnSocketsOnly(t *testing.T) {
	orig := readPCBList
	t.Cleanup(func() { readPCBList = orig })
	for _, c := range []struct {
		name       string
		count      uint32
		restricted bool
	}{
		{"header counts the same", 0, false},
		{"header counts more", 5, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// two xinpgen headers and no records in between
			buf := make([]byte, 48)
			for _, off := range []int{0, 24} {
				buf[off] = 24
				*(*uint32)(unsafe.Pointer(&buf[off+4])) = c.count
			}
			readPCBList = func(string) ([]byte, error) { return buf, nil }

			_, restricted, err := findProcessNameByPCBList("net.inet.tcp.pcblist_n", TCP, netip.MustParseAddr("127.0.0.1"), 1)
			assert.ErrorIs(t, err, ErrNotFound)
			assert.Equal(t, c.restricted, restricted)
		})
	}
}

func TestFindProcessNameNotFound(t *testing.T) {
	// nothing uses local port 1 as a source port; the table itself is
	// restricted or not depending on the macOS version
	_, _, err := findProcessName(TCP, netip.MustParseAddr("127.0.0.1"), 1)
	assert.ErrorIs(t, err, ErrNotFound)

	_, err = findProcessBySocketScan(TCP, netip.MustParseAddr("127.0.0.1"), 1)
	assert.ErrorIs(t, err, ErrNotFound)
}

func BenchmarkFindProcessName(b *testing.B) {
	ip := netip.MustParseAddr("127.0.0.1")
	b.Run("pcblist", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = findProcessName(TCP, ip, 1)
		}
	})
	b.Run("socket scan miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = findProcessBySocketScan(TCP, ip, 1)
		}
	})
}
