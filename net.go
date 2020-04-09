// Author:  Niels A.D.
// Project: gamenetworkingsockets (https://github.com/nielsAD/gns)
// License: Mozilla Public License, v2.0

package gns

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Errors
var (
	ErrInvalidConnection   = errors.New("gns: Invalid connection")
	ErrInvalidListenSocket = errors.New("gns: Invalid listensocket")
	ErrInvalidPollGroup    = errors.New("gns: Invalid pollgroup")
	ErrClosedConnection    = errors.New("gns: Use of closed connection")
	ErrClosedListener      = errors.New("gns: Use of closed listener")
	ErrMessageTooBig       = errors.New("gns: Message too big in size")
	ErrMessageDropped      = errors.New("gns: Message dropped due to buffer limit")
	ErrDeadline            = &errDeadline{}
)

// errDeadline error
type errDeadline struct{}

// Error implements error interface
func (err errDeadline) Error() string { return "gns: Deadline exceeded" }

// Timeout implements os.timeout to return true on os.Timeout()
func (err errDeadline) Timeout() bool { return true }

// ErrRemoteClosed error
type ErrRemoteClosed struct {
	EndReason ConnectionEndReason
	EndDebug  string
}

func (err ErrRemoteClosed) Error() string {
	return err.EndDebug
}

func newTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return timer
}

// Listener implements net.Listener
type Listener struct {
	handle ListenSocket
	mut    sync.Mutex

	// Accept() variables
	amut      sync.Mutex
	achan     chan *Conn
	adeadline time.Time
	atimer    *time.Timer
}

var listenmut sync.Mutex
var listeners = map[ListenSocket]*Listener{}

// Listen acts like net.Listen for a GNS interface.
func Listen(laddr *net.UDPAddr, config ConfigMap) (*Listener, error) {
	if err := startPoll(); err != nil {
		return nil, err
	}

	var addr net.UDPAddr
	if laddr != nil {
		addr = *laddr
	}
	if addr.Port == 0 {
		l, err := net.ListenUDP("udp", &addr)
		if err != nil {
			return nil, err
		}

		addr = *l.LocalAddr().(*net.UDPAddr)
		l.Close()
	}

	handle := CreateListenSocketIP(NewIPAddr(&addr), config)
	if handle == InvalidListenSocket {
		return nil, ErrInvalidListenSocket
	}

	l := &Listener{
		handle: handle,
		achan:  make(chan *Conn, 1024),
		atimer: newTimer(),
	}

	listenmut.Lock()
	listeners[handle] = l
	listenmut.Unlock()

	return l, nil
}

// Handle returns underlying ListenSocket
func (l *Listener) Handle() ListenSocket {
	l.mut.Lock()
	handle := l.handle
	l.mut.Unlock()
	return handle
}

// AcceptGNS waits for and returns the next connection to the listener.
func (l *Listener) AcceptGNS() (*Conn, error) {
	// Limit to a single Accept() at a time
	l.amut.Lock()
	defer l.amut.Unlock()

	l.mut.Lock()
	han := l.handle
	adl := l.adeadline
	l.mut.Unlock()

	if han == InvalidListenSocket {
		return nil, ErrClosedListener
	} else if !adl.IsZero() && time.Now().After(adl) {
		return nil, ErrDeadline
	}

	for {
		select {
		case <-l.atimer.C:
			// time.Timer uses a buffered channel that might be filled with an "old"
			// value, so verify that we indeed passed the deadline
			l.mut.Lock()
			adl := l.adeadline
			l.mut.Unlock()

			if !adl.IsZero() && time.Now().After(adl) {
				return nil, ErrDeadline
			}
		case conn := <-l.achan:
			return conn, nil
		}
	}
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptGNS()
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	l.mut.Lock()
	defer l.mut.Unlock()

	if l.handle == InvalidListenSocket {
		return ErrClosedListener
	}

	listenmut.Lock()
	delete(listeners, l.handle)
	listenmut.Unlock()

	// Set deadline in the past
	l.adeadline = time.Time{}.Add(1)
	l.atimer.Reset(-1)

	l.handle.Close()
	l.handle = InvalidListenSocket

	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	if addr := l.Handle().ListenAddr(); addr != nil {
		return addr.UDPAddr()
	}
	return nil
}

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (l *Listener) SetDeadline(t time.Time) error {
	l.mut.Lock()
	defer l.mut.Unlock()

	if l.handle == InvalidListenSocket {
		return ErrClosedListener
	}

	l.adeadline = t
	if !t.IsZero() {
		l.atimer.Reset(t.Sub(time.Now()))
	}

	return nil
}

// Conn implements net.handle
type Conn struct {
	handle Connection
	mut    sync.Mutex

	err     error
	nodelay bool
	linger  int

	// Read() variables
	rmut      sync.Mutex
	rerr      error
	rmsg      *Message
	ridx      int
	rchan     chan *Message
	rdeadline time.Time
	rtimer    *time.Timer

	// Write() variables
	wdeadline time.Time
}

var connections = map[Connection]*Conn{}
var connectmut sync.Mutex

func newConn(handle Connection) (*Conn, bool) {
	if handle == InvalidConnection {
		return nil, false
	}
	if !handle.SetPollGroup(pollgroup) {
		handle.Close(0, "", false)
		return nil, false
	}

	c := &Conn{
		handle: handle,
		rchan:  make(chan *Message, 1024),
		rtimer: newTimer(),
	}
	return c, true
}

// DialContext acts like net.DialContext for a GNS interface.
func DialContext(ctx context.Context, raddr *net.UDPAddr, config ConfigMap) (*Conn, error) {
	if err := startPoll(); err != nil {
		return nil, err
	}

	connectmut.Lock()
	handle := ConnectByIPAddress(NewIPAddr(raddr), config)

	conn, ok := newConn(handle)
	if !ok {
		connectmut.Unlock()
		return nil, ErrInvalidConnection
	}

	connections[handle] = conn
	connectmut.Unlock()

	select {
	case <-conn.rchan:
		// Wait until we are in a connected/failed state
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	conn.mut.Lock()
	err := conn.rerr
	conn.mut.Unlock()

	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// Dial acts like net.Dial for a GNS interface.
func Dial(raddr *net.UDPAddr, config ConfigMap) (*Conn, error) {
	return DialContext(context.Background(), raddr, config)
}

// Pipe creates a full duplex network connection; both ends implement the
// Conn interface. Reads on one end are matched with writes on the other,
// copying data between the two.
func Pipe(loopback bool, id1 *Identity, id2 *Identity) (*Conn, *Conn, error) {
	if err := startPoll(); err != nil {
		return nil, nil, err
	}

	han1, han2 := CreateSocketPair(loopback, id1, id2)
	conn1, ok1 := newConn(han1)
	conn2, ok2 := newConn(han2)

	if !ok1 || !ok2 {
		conn1.Close()
		conn2.Close()
		return nil, nil, ErrInvalidConnection
	}

	connectmut.Lock()
	connections[han1] = conn1
	connections[han2] = conn2
	connectmut.Unlock()

	return conn1, conn2, nil
}

func (c *Conn) setReadError(err error) {
	c.mut.Lock()
	if c.rerr == nil {
		c.rerr = err
	}
	c.mut.Unlock()
}

// Handle returns underlying Connection
func (c *Conn) Handle() Connection {
	c.mut.Lock()
	handle := c.handle
	c.mut.Unlock()
	return handle
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (int, error) {
	// Limit to a single Accept() at a time
	c.rmut.Lock()
	defer c.rmut.Unlock()

	c.mut.Lock()
	han := c.handle
	rdl := c.rdeadline
	err := c.rerr
	c.mut.Unlock()

	if han == InvalidConnection {
		return 0, ErrClosedConnection
	} else if !rdl.IsZero() && time.Now().After(rdl) {
		return 0, ErrDeadline
	}

	for c.rmsg == nil {
		if err != nil {
			// Drain message queue, return error when empty
			select {
			case msg := <-c.rchan:
				c.rmsg = msg
			default:
				return 0, err
			}
		} else {
			// Wait for message
			for {
				select {
				case <-c.rtimer.C:
					// time.Timer uses a buffered channel that might be filled with an "old"
					// value, so verify that we indeed passed the deadline
					c.mut.Lock()
					rdl := c.rdeadline
					c.mut.Unlock()

					if rdl.IsZero() || !time.Now().After(rdl) {
						continue
					}

					return 0, ErrDeadline
				case msg := <-c.rchan:
					if msg == nil {
						// close_wait state, c.rerr will be set with more info
						c.mut.Lock()
						if c.rerr == nil {
							c.rerr = io.EOF
						}
						err = c.rerr
						c.mut.Unlock()
					} else {
						c.rmsg = msg
					}
				}

				// we did not exceed deadline, break waiting loop
				break
			}
		}

		// when we get here, either c.rmsg != nil OR c.rerr != nil
	}

	n := copy(b, c.rmsg.Payload()[c.ridx:])
	if c.ridx += n; c.ridx >= c.rmsg.Size() {
		c.ridx = 0
		c.rmsg.Release()
		c.rmsg = nil
	}

	return n, nil
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.mut.Lock()
	nod := c.nodelay
	c.mut.Unlock()

	flags := SendReliable
	if nod {
		flags |= SendNoNagle
	}

	n, l := 0, len(b)
	for l > 0 {
		lim := l
		if lim > MaxMessageSizeSend {
			lim = MaxMessageSizeSend
		}

		nn, err := c.SendMessage(b[:lim], flags)
		n += nn
		l -= nn

		if err != nil {
			return n, err
		}

		b = b[nn:]
	}
	return n, nil
}

// SendMessage to the remote host on the connection.
func (c *Conn) SendMessage(b []byte, flags SendFlags) (int, error) {
	c.mut.Lock()
	han := c.handle
	wdl := c.wdeadline
	c.mut.Unlock()

	if han == InvalidConnection {
		return 0, ErrClosedConnection
	} else if !wdl.IsZero() && time.Now().After(wdl) {
		return 0, ErrDeadline
	} else if len(b) == 0 {
		return 0, nil
	} else if len(b) > MaxMessageSizeSend {
		return 0, ErrMessageTooBig
	}

	for {
		_, res := han.SendMessage(b, flags)
		switch res {
		case ResultLimitExceeded:
			c.mut.Lock()
			wdl := c.wdeadline
			c.mut.Unlock()

			sleep := wdl.Sub(time.Now())
			if !wdl.IsZero() && sleep < 0 {
				return 0, ErrDeadline
			}

			if stat := han.QuickConnectionStatus(); stat != nil && stat.QueueTime > 0 && (sleep < 0 || stat.QueueTime < sleep) {
				sleep = stat.QueueTime
			}
			if sleep < 0 || sleep > time.Second {
				sleep = time.Second
			}

			time.Sleep(sleep)

		case ResultOK:
			return len(b), nil
		case ResultInvalidParam, ResultInvalidState:
			return 0, ErrClosedConnection
		case ResultNoConnection:
			return 0, io.EOF
		default:
			return 0, res
		}
	}
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.handle == InvalidConnection {
		return ErrClosedConnection
	}

	connectmut.Lock()
	delete(connections, c.handle)
	connectmut.Unlock()

	// Set deadline in the past
	c.wdeadline = time.Time{}.Add(1)
	c.rdeadline = time.Time{}.Add(1)
	c.rtimer.Reset(-1)

	if c.linger > 0 {
		handle := c.handle

		// Manually handle linger; wait set seconds for outgoing packets to flush
		go func() {
			handle.SendMessage([]byte{}, SendReliable)
			handle.Flush()

			for i := 0; i < c.linger; i++ {
				status := handle.QuickConnectionStatus()
				if status == nil || status.State != ConnectionStateConnected || (status.PendingReliable == 0 && status.SentUnackedReliable == 0) {
					break
				}
				time.Sleep(time.Second)
			}

			handle.Close(0, "", false)
		}()
	} else {
		c.handle.Close(0, "", c.linger < 0)
	}

	c.handle = InvalidConnection

	c.rmut.Lock()
	if c.rmsg != nil {
		c.rmsg.Release()
	}
	for i := 0; i < len(c.rchan); i++ {
		(<-c.rchan).Release()
	}
	c.rmut.Unlock()

	return nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	if info := c.Handle().Info(); info != nil {
		if addr := info.ListenSocket().ListenAddr(); addr != nil {
			return addr.UDPAddr()
		}
	}

	return nil
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	if info := c.Handle().Info(); info != nil {
		return info.RemoteAddr().UDPAddr()
	}

	return nil
}

// SetLinger sets the behavior of Close on a connection which still
// has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), the operating system finishes sending the
// data in the background.
//
// If sec == 0, the operating system discards any unsent or
// unacknowledged data.
//
// If sec > 0, the data is sent in the background as with sec < 0. On
// some operating systems after sec seconds have elapsed any remaining
// unsent data may be discarded.
func (c *Conn) SetLinger(linger int) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.handle == InvalidConnection {
		return ErrClosedConnection
	}

	c.linger = linger
	return nil
}

// SetNoDelay controls whether the operating system should delay
// packet transmission in hopes of sending fewer packets (Nagle's
// algorithm).
func (c *Conn) SetNoDelay(noDelay bool) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.handle == InvalidConnection {
		return ErrClosedConnection
	}

	c.nodelay = true
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Conn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if werr := c.SetWriteDeadline(t); werr != nil && err == nil {
		return werr
	}
	return err
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.handle == InvalidConnection {
		return ErrClosedConnection
	}

	c.rdeadline = t
	if !t.IsZero() {
		c.rtimer.Reset(t.Sub(time.Now()))
	}

	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	if c.handle == InvalidConnection {
		return ErrClosedConnection
	}

	c.wdeadline = t
	return nil
}

var pollgroup PollGroup
var closewait []*Conn

func statusChanged(cb *StatusChangedCallbackInfo) {
	conn := cb.Conn()
	info := cb.Info()
	state := info.State()

	switch state {
	case ConnectionStateNone:
		connectmut.Lock()
		delete(connections, conn)
		connectmut.Unlock()

	case ConnectionStateClosedByPeer, ConnectionStateProblemDetectedLocally:
		connectmut.Lock()
		c, ok := connections[conn]
		connectmut.Unlock()

		if !ok {
			conn.Close(0, "", false)
			return
		}

		end := info.EndReason()
		err := io.EOF
		if state != ConnectionStateClosedByPeer || end != ConnectionEndAppGeneric {
			err = &ErrRemoteClosed{
				EndReason: end,
				EndDebug:  info.EndDebug(),
			}
		}
		c.setReadError(err)

		if cb.OldState() != ConnectionStateConnected {
			// Signal Dial() that we will not connect
			c.rchan <- nil
		}

		closewait = append(closewait, c)

	case ConnectionStateConnecting:
		sock := info.ListenSocket()
		if sock == InvalidListenSocket {
			// This connection was initiated via Dial()
			return
		}

		listenmut.Lock()
		l, ok := listeners[sock]
		listenmut.Unlock()

		if !ok || conn.Accept() != ResultOK {
			conn.Close(0, "", false)
			return
		}

		c, ok := newConn(conn)
		if !ok {
			conn.Close(0, "", false)
			return
		}

		connectmut.Lock()
		connections[conn] = c
		connectmut.Unlock()

		select {
		case l.achan <- c:
			// Appended to Accept() queue
		default:
			// Accept buffer full, drop the connection
			conn.Close(0, "", false)
		}

	case ConnectionStateConnected:
		if info.ListenSocket() != InvalidListenSocket {
			// This connection was accepted on a Listener
			return
		}

		connectmut.Lock()
		c, ok := connections[conn]
		connectmut.Unlock()

		if !ok {
			conn.Close(0, "", false)
			return
		}

		// Signal Dial() that we are now connected
		c.rchan <- nil
	}
}

func closewaits() {
	if len(closewait) > 0 {
		failed := 0
		for _, c := range closewait {
			select {
			case c.rchan <- nil:
				// Signal Read() that no new messages will be queued
			default:
				closewait[failed] = c
				failed++
			}
		}
		closewait = closewait[:failed]
	}
}

var pollv uint32
var pollw sync.WaitGroup

func poll() {
	var m [1024]*Message
	for atomic.LoadUint32(&pollv) != 0 {
		RunCallbacks(statusChanged)
		n := pollgroup.ReceiveMessages(m[:])
		if n == 0 {
			closewaits()
			time.Sleep(time.Millisecond * 5)
			continue
		}

		connectmut.Lock()
		for i := 0; i < n; i++ {
			msg := m[i]
			c, ok := connections[msg.Conn()]
			if !ok || c.rerr != nil {
				msg.Release()
				continue
			}

			if msg.Size() == 0 {
				msg.Release()
				c.setReadError(io.EOF)

				select {
				case c.rchan <- nil:
					// Signal EOF
				default:
					// Ignore full buffer
				}

				continue
			}

			select {
			case c.rchan <- msg:
				// Appended to Read() queue
			default:
				// Read buffer full, drop the message
				msg.Release()
				c.setReadError(ErrMessageDropped)
			}
		}
		connectmut.Unlock()

		time.Sleep(time.Millisecond)
	}
	pollw.Done()
}

func startPoll() error {
	connectmut.Lock()
	defer connectmut.Unlock()

	if pollgroup == InvalidPollGroup {
		if err := Init(nil); err != nil {
			return err
		}

		pollgroup = NewPollGroup()
		if pollgroup == InvalidPollGroup {
			return ErrInvalidPollGroup
		}

		atomic.StoreUint32(&pollv, ^(uint32)(0))
		pollw.Add(1)
		go poll()
	}

	return nil
}

// Init GNS
func Init(id *Identity) error {
	return InitLibrary(id)
}

// Kill GNS
func Kill() {
	atomic.StoreUint32(&pollv, 0)
	pollw.Wait()

	connectmut.Lock()
	pollgroup.Close()
	pollgroup = InvalidPollGroup
	KillLibrary()
	connectmut.Unlock()
}
