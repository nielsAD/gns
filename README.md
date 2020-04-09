GameNetworkingSockets
=====================
[![build](https://github.com/nielsAD/gns/workflows/test/badge.svg)](https://github.com/nielsAD/gns/actions/)
[![GoDoc](https://godoc.org/github.com/nielsAD/gns?status.svg)](https://godoc.org/github.com/nielsAD/gns)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

Package gns provides golang bindings for the [GameNetworkingSockets](https://github.com/ValveSoftware/GameNetworkingSockets/) library.

### GameNetworkingSockets features

* Connection-oriented API (like TCP)
* ... but message-oriented (like UDP), not stream-oriented.
* Supports both reliable and unreliable message types
* Messages can be larger than underlying MTU.  The protocol performs
fragmentation, reassembly, and retransmission for reliable messages.
* Encryption. AES-GCM-256 per packet, [Curve25519](https://cr.yp.to/ecdh.html) for
key exchange and cert signatures. The details for shared key derivation and
per-packet IV are based on the [design](https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/edit?usp=sharing)
used by Google's QUIC protocol.
* Tools for simulating loss and detailed stats measurement.
* IPv4 + IPv6

### gns features

* Support for dynamic/static linking
* API documentation available via `godoc`
* Compatible with [net.Conn](https://golang.org/pkg/net/#Conn) and [net.Listener](https://golang.org/pkg/net/#Listener)

Example
-------

```go
func Example() {
	// GameNetworkingSockets uses a fixed transmission rate, set to 512K/s
	cfg := gns.ConfigMap{
		gns.ConfigSendRateMin: 512 * 1024,
		gns.ConfigSendRateMax: 512 * 1024,
	}

	l, err := gns.Listen(&net.UDPAddr{IP: net.IP{127, 0, 0, 1}}, cfg)
	if err != nil {
		log.Fatal("Listen: ", err)
	}
	defer l.Close()

	gns.SetGlobalConfigValue(gns.ConfigFakePacketLagRecv, 10.0)
	gns.SetGlobalConfigValue(gns.ConfigFakePacketLagSend, 10.0)
	gns.SetGlobalConfigValue(gns.ConfigFakePacketLossRecv, 5.0)
	gns.SetGlobalConfigValue(gns.ConfigFakePacketLossSend, 5.0)

	// send a burst of 2MiB random bytes with 20ms lag and ~10% packet loss
	var in [2 * 1024 * 1024]byte
	rand.Read(in[:])

	go func() {
		c, err := gns.Dial(l.Addr().(*net.UDPAddr), cfg)
		if err != nil {
			log.Fatal("Dial: ", err)
		}
		defer c.Close()

		// Linger for as long as it takes
		c.SetLinger(-1)

		if _, err := io.Copy(c, bytes.NewReader(in[:])); err != nil {
			log.Fatal("Copy: ", err)
		}
	}()

	conn, err := l.AcceptGNS()
	if err != nil {
		log.Fatal("Accept: ", err)
	}
	defer conn.Close()

	out, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Fatal("Read: ", err)
	}

	fmt.Println("Compare(in, out) ==", bytes.Compare(out, in[:]) == 0)
	// Output: Compare(in, out) == true
}
```