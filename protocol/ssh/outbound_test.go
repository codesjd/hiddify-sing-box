package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer starts a minimal in-process SSH server that accepts any password and answers
// global requests (e.g. "keepalive@openssh.com") only while respond is non-zero, letting a test
// simulate a connection that has silently stopped responding (the case a NAT/firewall dropping the
// mapping looks like: writes may still succeed, but nothing ever replies) rather than one that
// fails immediately. Returns the listen address and the atomic flag.
func startTestSSHServer(t *testing.T) (addr string, respond *atomic.Bool) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	respond = &atomic.Bool{}
	respond.Store(true)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer sconn.Close()
				go func() {
					for newChan := range chans {
						newChan.Reject(ssh.Prohibited, "no channels in this test")
					}
				}()
				for req := range reqs {
					if !respond.Load() {
						continue // simulate a connection that stopped responding
					}
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}()
		}
	}()

	return ln.Addr().String(), respond
}

func dialTestClient(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return client
}

// TestKeepAliveClosesUnresponsiveConnection verifies the actual bug this closes: a connection that
// stops answering (simulating a NAT/firewall silently dropping the mapping) is detected and closed
// by keepAlive, rather than being reused forever - which is what let a single dead connection make
// every subsequent dial/read on this outbound hang instead of failing, showing up as wildly
// inconsistent latency rather than a clean disconnect.
func TestKeepAliveClosesUnresponsiveConnection(t *testing.T) {
	addr, respond := startTestSSHServer(t)
	client := dialTestClient(t, addr)
	respond.Store(false)

	s := &Outbound{ctx: context.Background()}
	go s.keepAlive(client, 20*time.Millisecond, 100*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- client.Wait() }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("keepAlive did not close the unresponsive connection in time")
	}
}

// TestKeepAliveLeavesHealthyConnectionOpen is the inverse check: a connection that keeps replying
// normally must not be closed out from under active traffic.
func TestKeepAliveLeavesHealthyConnectionOpen(t *testing.T) {
	addr, _ := startTestSSHServer(t)
	client := dialTestClient(t, addr)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Outbound{ctx: ctx}
	go s.keepAlive(client, 20*time.Millisecond, 100*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- client.Wait() }()

	select {
	case err := <-done:
		t.Fatalf("healthy connection was closed unexpectedly: %v", err)
	case <-time.After(300 * time.Millisecond):
		// Still open after several keepalive intervals, as expected.
	}
}
