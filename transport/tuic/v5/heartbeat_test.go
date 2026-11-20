package v5

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestClientSendsProtocolHeartbeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	server, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		NextProtos:   []string{"h3"},
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	defer server.Close()
	client := NewClient(&ClientOption{Heartbeat: 25 * time.Millisecond}, false, func(ctx context.Context) (*quic.Conn, error) {
		return quic.DialAddr(ctx, server.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	})
	defer client.forceClose()
	_, err = client.getQuicConn(ctx)
	require.NoError(t, err)
	peer, err := server.Accept(ctx)
	require.NoError(t, err)
	packet, err := peer.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte{VER, byte(HeartbeatType)}, packet)
}
