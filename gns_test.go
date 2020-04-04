// Author:  Niels A.D.
// Project: gamenetworkingsockets (https://github.com/nielsAD/gns)
// License: Mozilla Public License, v2.0

package gns_test

import (
	"net"
	"testing"

	"github.com/nielsAD/gns"
)

func TestConfigValue(t *testing.T) {
	if val := gns.NewConfigValue(gns.ConfigSendBufferSize, 333); val.Int32() != 333 {
		t.Fatal("Int ConfigValue mismatch")
	}
	if val := gns.NewConfigValue(gns.ConfigSendBufferSize, int32(12345)); val.Int32() != 12345 {
		t.Fatal("Int32 ConfigValue mismatch")
	}
	if val := gns.NewConfigValue(gns.ConfigSendBufferSize, int64(67890)); val.Int64() != 67890 {
		t.Fatal("Int64 ConfigValue mismatch")
	}
	if val := gns.NewConfigValue(gns.ConfigSendBufferSize, 22.0); val.Float() != 22.0 {
		t.Fatal("Float ConfigValue mismatch")
	}
}

func TestIdentity(t *testing.T) {
	if id := gns.ParseIdentity("ip:127.0.0.1"); id == nil || id.Type() != gns.IdentityTypeIPAddress {
		t.Fatal("IP identity expected")
	} else if !id.Valid() || id.String() != "ip:127.0.0.1" {
		t.Fatal("IP identity mismatch '" + id.String() + "'")
	}

	if id := gns.ParseIdentity("str:GenericString"); id == nil || id.Type() != gns.IdentityTypeGenericString {
		t.Fatal("GenericString identity expected")
	} else if !id.Valid() || id.String() != "str:GenericString" {
		t.Fatal("GenericString identity mismatch '" + id.String() + "'")
	}

	if id := gns.ParseIdentity("gen:47656e657269634279746573"); id == nil || id.Type() != gns.IdentityTypeGenericBytes {
		t.Fatal("GenericBytes identity expected")
	} else if !id.Valid() || id.String() != "gen:47656e657269634279746573" {
		t.Fatal("GenericBytes identity mismatch '" + id.String() + "'")
	}

	if id := gns.ParseIdentity("RandomString"); id.Valid() {
		t.Fatal("nil expected for random string")
	}
}

func TestIPAddr(t *testing.T) {
	ref := net.UDPAddr{
		IP:   net.IP{1, 2, 3, 4},
		Port: 5678,
	}

	in := gns.NewIPAddr(&ref)
	out := in.UDPAddr()
	if ref.String() != out.String() {
		t.Fatal("ip4: in != out", in, *out)
	}

	ref.IP = net.IPv6linklocalallrouters

	in = gns.NewIPAddr(&ref)
	out = in.UDPAddr()
	if ref.String() != out.String() {
		t.Fatal("ip6: in != out", in, *out)
	}
}

func TestMessage(t *testing.T) {
	if err := gns.InitLibrary(nil); err != nil {
		t.Fatal(err)
	}
	defer gns.KillLibrary()

	msg := gns.InvalidConnection.NewMessage(123, gns.SendReliableNoNagle)
	if msg == nil {
		t.Fatal("NewMessage")
	}
	defer msg.Release()

	if msg.Conn() != gns.InvalidConnection {
		t.Fatal("Conn")
	}
	if msg.Size() != 123 {
		t.Fatal("Size")
	}
	if msg.Flags() != gns.SendReliableNoNagle {
		t.Fatal("Flags")
	}
}

func TestListenSocket(t *testing.T) {
	if err := gns.InitLibrary(nil); err != nil {
		t.Fatal(err)
	}
	defer gns.KillLibrary()

	gns.SetDebugOutputFunction(gns.DebugOutputTypeEverything, func(typ gns.DebugOutputType, msg string) {
		t.Log("[DEBUG]", typ, msg)
	})

	if gns.InvalidListenSocket.Close() {
		t.Fatal("InvalidListenSocket.Close")
	}

	addr := net.UDPAddr{IP: net.IPv6loopback, Port: 44696}
	if l := gns.CreateListenSocketIP(gns.NewIPAddr(&addr), nil); l == gns.InvalidListenSocket {
		t.Fatal("CreateListenSocketIP")
	} else if !l.Close() {
		t.Fatal("CloseListenSocket")
	}

	addr.Port++
	if l := gns.CreateListenSocketIP(gns.NewIPAddr(&addr), gns.ConfigMap{
		gns.ConfigTimeoutInitial:   10_000,
		gns.ConfigTimeoutConnected: 20_000,
	}); l == gns.InvalidListenSocket {
		t.Fatal("CreateListenSocketIP with config")
	} else if !l.Close() {
		t.Fatal("CloseListenSocket with config")
	}
}
