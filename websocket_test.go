package forwardproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
)

func TestParseWebSocketTarget(t *testing.T) {
	payload := append([]byte{1, 3, 11}, []byte("example.com")...)
	payload = append(payload, 0, 0)
	host, port, err := parseWebSocketTarget(payload)
	if err != nil || host != "example.com" || port != 0 {
		t.Fatalf("parseWebSocketTarget domain: %v %q %d", err, host, port)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 443)
	_, port, err = parseWebSocketTarget(
		append([]byte{1, 1, 127, 0, 0, 1}, portBytes...))
	if err != nil || port != 443 {
		t.Fatalf("parseWebSocketTarget IPv4: %v %d", err, port)
	}
}

func TestWebSocketTunnel(t *testing.T) {
	const payloadSize = 0x10000

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetListener.Close()
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(bytes.Repeat([]byte{0x5a}, payloadSize))
	}()

	handler := Handler{
		WebSocket:       true,
		AuthCredentials: [][]byte{EncodeAuthCredentials("user", "pass")},
		DialTimeout:     caddy.Duration(5 * time.Second),
		dialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		aclRules:        []aclRule{&aclAllRule{allow: true}},
	}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return nil
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replacer := caddy.NewReplacer()
		r = r.WithContext(context.WithValue(
			r.Context(), caddy.ReplacerCtxKey, replacer))
		err := handler.ServeHTTP(w, r, next)
		if err == nil {
			return
		}
		var handlerErr caddyhttp.HandlerError
		if errors.As(err, &handlerErr) {
			http.Error(w, handlerErr.Error(), handlerErr.StatusCode)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/naive"
	if _, response, err := websocket.DefaultDialer.Dial(wsURL, nil); err == nil {
		t.Fatal("unauthenticated WebSocket dial unexpectedly succeeded")
	} else if response == nil || response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated response = %v, want 407", response)
	}

	header := http.Header{}
	header.Set("Proxy-Authorization", "Basic "+
		string(EncodeAuthCredentials("user", "pass")))
	header.Set("Padding", strings.Repeat("!", 30))
	header.Set("Padding-Type-Request", "1,0")
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("authenticated WebSocket dial: %v", err)
	}
	defer conn.Close()
	if response.Header.Get("Padding-Type-Reply") != "1" {
		t.Fatal("server did not negotiate Variant 1 padding")
	}
	if response.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatal("server negotiated WebSocket compression")
	}

	address := targetListener.Addr().(*net.TCPAddr)
	target := append([]byte{1, 1}, address.IP.To4()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(address.Port))
	if err := conn.WriteMessage(
		websocket.BinaryMessage, append(target, port...)); err != nil {
		t.Fatalf("send target: %v", err)
	}
	if _, status, err := conn.ReadMessage(); err != nil ||
		len(status) != 1 || status[0] != 0 {
		t.Fatalf("read status: %v %x", err, status)
	}

	received := 0
	paddedFrames := 0
	for received < payloadSize {
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read payload: %v", err)
		}
		if paddedFrames < NumFirstPaddings {
			if len(message) < 3 {
				t.Fatalf("short padded frame: %x", message)
			}
			payloadLen := int(message[0])<<8 | int(message[1])
			paddingLen := int(message[2])
			if len(message) != 3+payloadLen+paddingLen {
				t.Fatalf("invalid padded frame lengths: got %d, want %d",
					len(message), 3+payloadLen+paddingLen)
			}
			message = message[3 : 3+payloadLen]
			paddedFrames++
		}
		for _, b := range message {
			if b != 0x5a {
				t.Fatalf("unexpected payload byte %#x", b)
			}
		}
		received += len(message)
	}
	if received != payloadSize {
		t.Fatalf("received %d bytes, want %d", received, payloadSize)
	}
}
