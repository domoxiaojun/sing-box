package sbctl_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/sagernet/sing-box/experimental/v2rayapi"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type object = map[string]any

// The integration test runs only against disposable containers in Linux CI.
func TestImage(t *testing.T) {
	image := os.Getenv("SBCTL_TEST_IMAGE")
	if image == "" {
		t.Fatal("SBCTL_TEST_IMAGE must select a locally built candidate image")
	}
	version := command(t, "docker", "run", "--rm", "--network", "none", image, "version")
	if !strings.Contains(version, "sing-box version 1.12.9\n") {
		t.Fatalf("unexpected version: %s", version)
	}
	for _, tag := range []string{"with_gvisor", "with_quic", "with_dhcp", "with_wireguard", "with_utls", "with_acme", "with_clash_api", "with_tailscale", "with_v2ray_api"} {
		if !strings.Contains(version, tag) {
			t.Fatalf("missing build tag %s", tag)
		}
	}
	t.Log(strings.TrimSpace(version))

	dir := t.TempDir()
	certificate(t, dir)
	password := randomHex(t)
	secret := randomHex(t)
	used := make(map[int]bool)
	port := func() int {
		for {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			if !used[p] {
				used[p] = true
				return p
			}
		}
	}
	apiPort, clashPort := port(), port()
	anyPort, tuicPort := port(), port()
	anySOCKS, tuicSOCKS := port(), port()
	anyUDP, tuicUDP := port(), port()

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(echo.Close)
	udpEcho, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpEcho.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, address, readErr := udpEcho.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buffer[:n], address)
		}
	}()
	udpEchoPort := udpEcho.LocalAddr().(*net.UDPAddr).Port
	serverTLS := object{"enabled": true, "certificate_path": "/test/cert.pem", "key_path": "/test/key.pem"}
	tuicTLS := object{"enabled": true, "certificate_path": "/test/cert.pem", "key_path": "/test/key.pem", "alpn": []string{"h3"}}
	clientTLS := object{"enabled": true, "server_name": "localhost", "certificate_path": "/test/cert.pem"}
	tuicClientTLS := object{"enabled": true, "server_name": "localhost", "certificate_path": "/test/cert.pem", "alpn": []string{"h3"}}
	const uuid = "e5d9062e-5e92-4edc-991a-d3b52b18f45f"
	writeJSON(t, dir, "server.json", object{
		"log": object{"level": "warn"},
		"inbounds": []object{
			{"type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": anyPort, "users": []object{{"name": "ci-anytls", "password": password}}, "tls": serverTLS},
			{"type": "tuic", "tag": "tuic-in", "listen": "127.0.0.1", "listen_port": tuicPort, "users": []object{{"name": "ci-tuic", "uuid": uuid, "password": password}}, "tls": tuicTLS},
		},
		"outbounds": []object{{"type": "direct", "tag": "direct"}},
		"experimental": object{
			"v2ray_api": object{"listen": address(apiPort), "stats": object{"enabled": true, "users": []string{"ci-anytls", "ci-tuic"}}},
			"clash_api": object{"external_controller": address(clashPort), "secret": secret},
		},
	})
	writeJSON(t, dir, "client.json", object{
		"log": object{"level": "warn"},
		"inbounds": []object{
			{"type": "mixed", "tag": "anytls-tcp", "listen": "127.0.0.1", "listen_port": anySOCKS},
			{"type": "mixed", "tag": "tuic-tcp", "listen": "127.0.0.1", "listen_port": tuicSOCKS},
			{"type": "direct", "tag": "anytls-udp", "listen": "127.0.0.1", "listen_port": anyUDP, "network": "udp", "override_address": "127.0.0.1", "override_port": udpEchoPort},
			{"type": "direct", "tag": "tuic-udp", "listen": "127.0.0.1", "listen_port": tuicUDP, "network": "udp", "override_address": "127.0.0.1", "override_port": udpEchoPort},
		},
		"outbounds": []object{
			{"type": "anytls", "tag": "anytls", "server": "127.0.0.1", "server_port": anyPort, "password": password, "tls": clientTLS},
			{"type": "tuic", "tag": "tuic", "server": "127.0.0.1", "server_port": tuicPort, "uuid": uuid, "password": password, "tls": tuicClientTLS},
		},
		"route": object{"rules": []object{
			{"inbound": []string{"anytls-tcp", "anytls-udp"}, "action": "route", "outbound": "anytls"},
			{"inbound": []string{"tuic-tcp", "tuic-udp"}, "action": "route", "outbound": "tuic"},
		}},
	})
	startContainer(t, image, dir, "server")
	connection, err := grpc.NewClient(address(apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = connection.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/GetSysStats", &pb.SysStatsRequest{}, &pb.SysStatsResponse{}, grpc.WaitForReady(true))
	cancel()
	if err != nil {
		t.Fatalf("V2Ray GetSysStats: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+address(clashPort)+"/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Clash API returned %s", response.Status)
	}
	startContainer(t, image, dir, "client")
	for _, protocol := range []struct {
		name       string
		socks, udp int
	}{{"anytls", anySOCKS, anyUDP}, {"tuic", tuicSOCKS, tuicUDP}} {
		t.Run(protocol.name, func(t *testing.T) {
			waitTCP(t, protocol.socks)
			user := "ci-" + protocol.name
			before := counters(t, connection, user)
			payload := bytes.Repeat([]byte("sbctl-tcp-echo-"), 4096)
			dialer, dialErr := proxy.SOCKS5("tcp", address(protocol.socks), nil, &net.Dialer{Timeout: 5 * time.Second})
			if dialErr != nil {
				t.Fatal(dialErr)
			}
			transport := &http.Transport{DialContext: func(_ context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
			resp, sendErr := client.Post(echo.URL, "application/octet-stream", bytes.NewReader(payload))
			if sendErr != nil {
				t.Fatal(sendErr)
			}
			actual, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(actual, payload) {
				t.Fatalf("TCP echo mismatch: status=%s bytes=%d error=%v", resp.Status, len(actual), readErr)
			}
			after := awaitGrowth(t, connection, user, before, int64(len(payload)))
			t.Logf("TCP user=%s uplink=%d downlink=%d", user, after[0]-before[0], after[1]-before[1])
			before = after
			packet, dialErr := net.DialTimeout("udp4", address(protocol.udp), time.Second)
			if dialErr != nil {
				t.Fatal(dialErr)
			}
			defer packet.Close()
			if deadlineErr := packet.SetDeadline(time.Now().Add(10 * time.Second)); deadlineErr != nil {
				t.Fatal(deadlineErr)
			}
			payload = bytes.Repeat([]byte("sbctl-udp-echo-"), 80)
			if _, sendErr = packet.Write(payload); sendErr != nil {
				t.Fatal(sendErr)
			}
			buffer := make([]byte, 2048)
			n, readErr := packet.Read(buffer)
			if readErr != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("UDP echo mismatch: bytes=%d error=%v", n, readErr)
			}
			after = awaitGrowth(t, connection, user, before, int64(len(payload)))
			t.Logf("UDP user=%s uplink=%d downlink=%d", user, after[0]-before[0], after[1]-before[1])
		})
	}
}

func command(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", name, err, output)
	}
	return string(output)
}

func startContainer(t *testing.T, image, dir, role string) {
	t.Helper()
	name := "sbctl-ci-" + role + "-" + strconv.Itoa(os.Getpid())
	args := []string{"run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--mount", "type=bind,src=" + dir + ",dst=/test,readonly"}
	command(t, "docker", append(append([]string{}, args...), image, "check", "-c", "/test/"+role+".json")...)
	t.Cleanup(func() {
		if t.Failed() {
			output, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("%s logs:\n%s", role, output)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	command(t, "docker", append(args, "--detach", "--name", name, image, "run", "-c", "/test/"+role+".json")...)
}

func writeJSON(t *testing.T, dir, name string, value object) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func certificate(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"cert.pem": {Type: "CERTIFICATE", Bytes: der}, "key.pem": {Type: "PRIVATE KEY", Bytes: private}} {
		if err = os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func address(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func waitTCP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address(port), 250*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("client listener did not start")
}

func counters(t *testing.T, connection *grpc.ClientConn, user string) [2]int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var response pb.QueryStatsResponse
	if err := connection.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &pb.QueryStatsRequest{Reset_: false}, &response); err != nil {
		t.Fatal(err)
	}
	var values [2]int64
	for _, stat := range response.Stat {
		for i, direction := range []string{"uplink", "downlink"} {
			if stat.Name == "user>>>"+user+">>>traffic>>>"+direction {
				values[i] = stat.Value
			}
		}
	}
	return values
}

func awaitGrowth(t *testing.T, connection *grpc.ClientConn, user string, before [2]int64, minimum int64) [2]int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var after [2]int64
	for time.Now().Before(deadline) {
		after = counters(t, connection, user)
		if after[0]-before[0] >= minimum && after[1]-before[1] >= minimum {
			return after
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("user=%s missing traffic growth: before=%v after=%v minimum=%d", user, before, after, minimum)
	return after
}
