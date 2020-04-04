// Author:  Niels A.D.
// Project: gamenetworkingsockets (https://github.com/nielsAD/gns)
// License: Mozilla Public License, v2.0

package gns_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"github.com/nielsAD/gns"
)

func TestInterface(t *testing.T) {
	var c net.Conn = &gns.Conn{}
	var l net.Listener = &gns.Listener{}
	c.Close()
	l.Close()
}

func TestPipe(t *testing.T) {
	gns.Init(nil)
	gns.SetDebugOutputFunction(gns.DebugOutputTypeEverything, func(typ gns.DebugOutputType, msg string) {
		t.Log("[DEBUG]", typ, msg)
	})
	defer gns.Kill()

	c1, c2, err := gns.Pipe(false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	defer c2.Close()

	var b [32]byte

	dl := time.Now().Add(1 * time.Millisecond)
	if err := c1.SetReadDeadline(dl); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Read(b[:]); err != gns.ErrDeadline {
		t.Fatal("Deadline error expected")
	}
	if time.Now().Before(dl) {
		t.Fatal("Did not wait until synchronous deadline")
	}

	if err := c1.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	dl = time.Now()
	go func() {
		time.Sleep(time.Millisecond * 5)
		c1.SetReadDeadline(dl)
	}()

	if _, err := c1.Read(b[:]); err != gns.ErrDeadline {
		t.Fatal("Async deadline error expected")
	}
	if time.Now().Sub(dl) < time.Millisecond*4 {
		t.Fatal("Did not wait until asynchronous deadline")
	}

	str := "Hello, world!"
	if _, err := c1.Write([]byte(str)); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Write([]byte(str)); err != nil {
		t.Fatal(err)
	}

	c1.SetReadDeadline(time.Now().Add(1 * time.Second))
	c2.SetReadDeadline(time.Now().Add(1 * time.Second))

	if n, err := c1.Read(b[:]); err != nil {
		t.Fatal(err)
	} else if n != len(str) {
		t.Fatal("Read size mismatch")
	} else if string(b[:n]) != str {
		t.Fatal("Read mismatch")
	}

	if n, err := c2.Read(b[:]); err != nil {
		t.Fatal(err)
	} else if n != len(str) {
		t.Fatal("Read size mismatch")
	} else if string(b[:n]) != str {
		t.Fatal("Read mismatch")
	}

	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Read(b[:]); err != gns.ErrClosedConnection {
		t.Fatal("Closed connection expected")
	}
	if _, err := c2.Read(b[:]); err != io.EOF {
		t.Fatal("EOF expected")
	}
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListen(t *testing.T) {
	gns.Init(nil)
	gns.SetDebugOutputFunction(gns.DebugOutputTypeEverything, func(typ gns.DebugOutputType, msg string) {
		t.Log("[DEBUG]", typ, msg)
	})
	defer gns.Kill()

	l, err := gns.Listen(&net.UDPAddr{IP: net.IPv6loopback}, nil)
	if err != nil {
		t.Fatal(err)
	}

	addr := l.Addr()
	if addr == nil {
		t.Fatal("Could not get listen addr")
	}

	l.SetDeadline(time.Now().Add(1 * time.Second))

	str := "Hello, world!"
	go func() {
		c, err := gns.Dial(addr.(*net.UDPAddr), nil)
		if err != nil {
			t.Log(err)
			return
		}
		defer c.Close()

		if _, err := c.Write([]byte(str)); err != nil {
			t.Log(err)
			return
		}

		time.Sleep(time.Millisecond * 50)
	}()

	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	var b [32]byte
	if n, err := conn.Read(b[:]); err != nil {
		t.Fatal(err)
	} else if n != len(str) {
		t.Fatal("Read size mismatch")
	} else if string(b[:n]) != str {
		t.Fatal("Read mismatch")
	}

	if _, err := conn.Read(b[:]); err != io.EOF {
		t.Log(err)
		t.Fatal("EOF expected")
	}
	conn.Close()

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func Example() {
	l, err := gns.Listen(&net.UDPAddr{IP: net.IP{127, 0, 0, 1}}, nil)
	if err != nil {
		log.Fatal("Listen: ", err)
	}
	defer l.Close()

	var in [1024 * 100]byte
	rand.Read(in[:])

	go func() {
		c, err := gns.Dial(l.Addr().(*net.UDPAddr), nil)
		if err != nil {
			log.Fatal("Dial: ", err)
		}
		defer c.Close()

		c.SetLinger(3)

		// Send 100 packets with 1024 bytes payload each
		p := in[:]
		for len(p) > 0 {
			if _, err := c.Write(p[:1024]); err != nil {
				log.Fatal("Copy: ", err)
			}
			p = p[1024:]
			time.Sleep(time.Millisecond / 10)
		}
	}()

	conn, err := l.Accept()
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
