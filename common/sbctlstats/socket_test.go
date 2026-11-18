package sbctlstats

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
)

type testOutbound struct{ adapter.Outbound }

func (testOutbound) Tag() string  { return "direct" }
func (testOutbound) Type() string { return "direct" }

func TestSocketLifecycleAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	manager := trafficcontrol.NewManager()
	s := New(manager, Options{SocketPath: path, NodeID: "node_test"})
	s.history = make([]connection, 3)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	defer scope.Close()
	for _, service := range []adapter.LifecycleService{manager, s} {
		if err := scope.Start(service.Name(), service, adapter.StartStateInitialize); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0660 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode: %v, %v", info, err)
	}

	for range 4 {
		client, server := net.Pipe()
		outbound := testOutbound{}
		tracked := manager.RoutedConnection(context.Background(), server, adapter.InboundContext{
			Inbound: "test-in", User: "local", OutboundChain: []adapter.Outbound{outbound},
		}, nil, outbound)
		done := make(chan error, 1)
		go func() { _, err := client.Write([]byte("data")); done <- err }()
		if n, err := tracked.Read(make([]byte, 4)); err != nil || n != 4 {
			t.Fatalf("tracked read = %d, %v", n, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		tracked.Close()
		client.Close()
	}
	r := query(t, path, request{Action: "snapshot", Limit: 1})
	if r.NodeID != "node_test" || r.Counters.UploadBytes != 16 || len(r.LocalUsers) != 1 || r.LocalUsers[0].UploadBytes != 16 {
		t.Fatalf("missing fast-closed traffic: %+v", r)
	}
	if !r.ConnectionsTruncated || !r.More || r.ConnectionSequence != 2 || len(r.Connections) != 1 || r.Connections[0].ClosedAt == "" {
		t.Fatalf("unexpected first page: %+v", r)
	}
	next := query(t, path, request{Action: "connections", RuntimeEpoch: r.RuntimeEpoch, AfterSequence: r.ConnectionSequence})
	if next.ConnectionsTruncated || next.More || next.ConnectionSequence != 4 || len(next.Connections) != 2 || next.Connections[0].Sequence != 3 {
		t.Fatalf("unexpected replay: %+v", next)
	}
}

func TestImageSocket(t *testing.T) {
	path := os.Getenv("SBCTL_TEST_SOCKET")
	if path == "" {
		t.Skip("image smoke test only")
	}
	r := query(t, path, request{Action: "snapshot"})
	if r.SchemaVersion != SchemaVersion || r.NodeID != "ci_node" || r.Error != "" || r.Counters == nil {
		t.Fatalf("unexpected image response: %+v", r)
	}
}

func query(t *testing.T, path string, req request) response {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(fmt.Errorf("dial stats socket: %w", err))
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var result response
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
