package forwardproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
)

var websocketUpgrader = websocket.Upgrader{
	EnableCompression: false,
	CheckOrigin:       func(*http.Request) bool { return true },
}

func (h Handler) serveWebSocket(w http.ResponseWriter, r *http.Request) error {
	responseHeader := http.Header{}
	padding := wantsVariant1Padding(r.Header)
	if padding {
		responseHeader.Set("Padding", randomPaddingHeader())
		responseHeader.Set("Padding-Type-Reply", "1")
	}
	conn, err := websocketUpgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	defer conn.Close()
	conn.SetReadLimit(1024 * 1024)

	timeout := time.Duration(h.DialTimeout)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	messageType, payload, err := conn.ReadMessage()
	if err != nil {
		return nil
	}
	if messageType != websocket.BinaryMessage {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{1})
		return nil
	}
	host, port, err := parseWebSocketTarget(payload)
	if err != nil {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{1})
		return nil
	}

	targetConn, err := h.dialContextCheckACL(
		r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil || targetConn == nil {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{4})
		return nil
	}
	defer targetConn.Close()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte{0}); err != nil {
		return nil
	}
	conn.SetReadDeadline(time.Time{})

	return dualStream(targetConn, &websocketReader{conn: conn},
		websocketWriter{conn: conn}, padding)
}

func wantsVariant1Padding(header http.Header) bool {
	if header.Get("Padding") == "" {
		return false
	}
	for _, value := range header.Values("Padding-Type-Request") {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) == "1" {
				return true
			}
		}
	}
	return false
}

func randomPaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := range padding {
		if i < 16 {
			padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
			bits >>= 4
		} else {
			padding[i] = '~'
		}
	}
	return string(padding)
}

func parseWebSocketTarget(payload []byte) (string, uint16, error) {
	if len(payload) < 4 || payload[0] != 1 {
		return "", 0, errors.New("invalid target header")
	}
	var host string
	var portOffset int
	switch payload[1] {
	case 1:
		if len(payload) < 8 {
			return "", 0, errors.New("short IPv4 address")
		}
		host, portOffset = net.IP(payload[2:6]).String(), 6
	case 3:
		length := int(payload[2])
		if len(payload) < 4+length {
			return "", 0, errors.New("short domain")
		}
		host, portOffset = string(payload[3:3+length]), 3+length
	case 4:
		if len(payload) < 20 {
			return "", 0, errors.New("short IPv6 address")
		}
		host, portOffset = net.IP(payload[2:18]).String(), 18
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", payload[1])
	}
	if len(payload) != portOffset+2 {
		return "", 0, errors.New("invalid target header length")
	}
	return host, binary.BigEndian.Uint16(payload[portOffset:]), nil
}

type websocketReader struct {
	conn   *websocket.Conn
	buffer []byte
}

func (r *websocketReader) Read(p []byte) (int, error) {
	for len(r.buffer) == 0 {
		messageType, payload, err := r.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			return 0, errors.New("non-binary WebSocket message")
		}
		r.buffer = payload
	}
	n := copy(p, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}

func (*websocketReader) Close() error { return nil }

type websocketWriter struct {
	conn *websocket.Conn
}

func (w websocketWriter) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w websocketWriter) CloseWrite() error {
	return w.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(10*time.Second))
}
