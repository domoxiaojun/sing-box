package sbctlagent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sbctlstats"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

type fakeInbound struct {
	adapter.Inbound
	tag   string
	users []option.AnyTLSUser
	mu    sync.Mutex
}

func (f *fakeInbound) Type() string { return "anytls" }
func (f *fakeInbound) Tag() string  { return f.tag }
func (f *fakeInbound) UpdateSBCTLUsers(u []option.AnyTLSUser) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append([]option.AnyTLSUser(nil), u...)
	return nil
}

type fakeInboundMgr struct {
	adapter.InboundManager
	items map[string]adapter.Inbound
}

func (m *fakeInboundMgr) Inbounds() []adapter.Inbound {
	var out []adapter.Inbound
	for _, v := range m.items {
		out = append(out, v)
	}
	return out
}
func (m *fakeInboundMgr) Get(tag string) (adapter.Inbound, bool) {
	v, ok := m.items[tag]
	return v, ok
}

type fakeBox struct {
	inMgr   *fakeInboundMgr
	stats   *sbctlstats.Service
	tm      *trafficcontrol.Manager
	scope   *adapter.Scope
	closed  atomic.Bool
}

func (b *fakeBox) Close() error {
	b.closed.Store(true)
	return b.scope.Close()
}
func (b *fakeBox) Inbound() adapter.InboundManager   { return b.inMgr }
func (b *fakeBox) SBCTLStats() *sbctlstats.Service   { return b.stats }

type noopOutbound struct{ adapter.Outbound }

func (noopOutbound) Tag() string  { return "direct" }
func (noopOutbound) Type() string { return "direct" }

func TestSupervisorHotUsersRollbackAndSeamlessLedger(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	stateDir := filepath.Join(dir, "state")

	initialCfg := `{"inbounds":[{"type":"anytls","tag":"anytls-in","listen":"127.0.0.1","listen_port":18443,"tls":{"enabled":true,"server_name":"hk.example.com"},"users":[{"name":"local_keep","password":"local_password_123456"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0640); err != nil {
		t.Fatal(err)
	}

	var factoryCalls atomic.Int32
	var activeBox *fakeBox
	var boxMu sync.Mutex

	factory := func(raw []byte) (BoxInstance, context.CancelFunc, error) {
		cfg, err := decodeObject(raw)
		if err != nil {
			return nil, nil, err
		}
		if cfg["invalid_trigger"] != nil {
			return nil, nil, errors.New("simulated invalid runtime configuration")
		}
		factoryCalls.Add(1)
		tm := trafficcontrol.NewManager()
		st := sbctlstats.New(tm, sbctlstats.Options{NodeID: "node_hk"})
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		_ = scope.Start(tm.Name(), tm, adapter.StartStateInitialize)
		_ = scope.Start(st.Name(), st, adapter.StartStateInitialize)

		inMap := map[string]adapter.Inbound{}
		for _, rv := range sliceVal(cfg["inbounds"]) {
			in := mapVal(rv)
			if strVal(in["type"]) == "anytls" {
				inMap[strVal(in["tag"])] = &fakeInbound{tag: strVal(in["tag"])}
			}
		}
		fb := &fakeBox{inMgr: &fakeInboundMgr{items: inMap}, stats: st, tm: tm, scope: scope}
		boxMu.Lock()
		activeBox = fb
		boxMu.Unlock()
		_, cancel := context.WithCancel(context.Background())
		return fb, cancel, nil
	}

	var registered atomic.Bool
	var telemetryCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/register":
			registered.Store(true)
			_ = json.NewEncoder(w).Encode(M{"node_id": "node_hk", "agent_token": "tok_test_123456"})
		case "/api/v1/agent/telemetry":
			telemetryCount.Add(1)
			var body M
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(M{"accepted": true, "acked_connection_seq": body["connection_next"], "live_subscribers": 1})
		case "/api/v1/agent/poll":
			_ = json.NewEncoder(w).Encode(M{"node_id": "node_hk", "poll_after_seconds": 1, "command": nil})
		case "/api/v1/agent/receipt":
			_ = json.NewEncoder(w).Encode(M{"accepted": true})
		}
	}))
	defer srv.Close()

	buildID := sha256Hex([]byte("test-engine"))
	sup, err := NewSupervisor(SupervisorConfig{
		ControlURL:       srv.URL,
		NodeID:           "node_hk",
		RegistrationCode: "reg_12345678901234567890123456789012",
		StateDir:         stateDir,
		ConfigPath:       cfgPath,
		Version:          "1.14.4-sbctl.2",
		BuildID:          buildID,
		Factory:          factory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.StartInitial(); err != nil {
		t.Fatal(err)
	}
	defer sup.StopInstance()

	if factoryCalls.Load() != 1 {
		t.Fatalf("expected 1 factory call, got %d", factoryCalls.Load())
	}

	// 1. Inspect and Configure (adopt node)
	insp, err := sup.HandleRPC(M{"action": "inspect", "public_host": "hk.example.com", "server_name": "hk.example.com"})
	if err != nil {
		t.Fatalf("inspect failed: %v", err)
	}
	cfgRes, err := sup.HandleRPC(M{
		"action":     "configure",
		"node_id":    "node_hk",
		"request_id": "njob_adopt01",
		"inspection": insp,
	})
	if err != nil || !boolVal(cfgRes["ready"]) {
		t.Fatalf("configure failed: %v, %+v", err, cfgRes)
	}
	callsAfterConfigure := factoryCalls.Load()

	// 2. Simulate traffic before user update
	boxMu.Lock()
	curBox := activeBox
	boxMu.Unlock()
	c1, s1 := net.Pipe()
	out := noopOutbound{}
	tr := curBox.tm.RoutedConnection(context.Background(), s1, adapter.InboundContext{
		Inbound: "anytls-in", User: "local_keep", OutboundChain: []adapter.Outbound{out},
	}, nil, out)
	go func() { _, _ = c1.Write([]byte("hello-world-12bytes")); c1.Close() }()
	_, _ = tr.Read(make([]byte, 64))
	tr.Close()

	// 3. Submit user credential update -> MUST hot-update in-place WITHOUT recreating Box!
	var eps []Endpoint
	_ = json.Unmarshal(canonicalBytes(cfgRes["endpoints"]), &eps)
	req := NodeRequest{
		SchemaVersion: 1,
		NodeID:        "node_hk",
		RequestID:     "req_hot001",
		NodeRevision:  1,
		TemplateHash:  strVal(cfgRes["template_hash"]),
		EngineBuildID: buildID,
		Users: []Credential{{
			UserID:       "usr_alice",
			Protocol:     "anytls",
			CredentialID: "cred_alice1",
			Generation:   1,
			Password:     "alice_secret_password_123",
			InboundID:    eps[0].InboundID,
		}},
		Revoked: []string{},
	}
	reqMap, _ := decodeObject(canonicalBytes(req))
	delete(reqMap, "payload_hash")
	req.PayloadHash = digestValue(reqMap)

	subRes, err := sup.HandleRPC(M{"action": "submit", "request": req})
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if strVal(mapVal(subRes["latest"])["state"]) != "verified" {
		t.Fatalf("expected immediate verified receipt, got %+v", subRes)
	}
	if factoryCalls.Load() != callsAfterConfigure {
		t.Fatalf("expected zero-downtime in-place user update without recreating box, factoryCalls=%d want=%d", factoryCalls.Load(), callsAfterConfigure)
	}
	inb, _ := curBox.inMgr.Get("anytls-in")
	fi := inb.(*fakeInbound)
	if len(fi.users) != 2 {
		t.Fatalf("expected preserved local user + usr_alice = 2 users, got %+v", fi.users)
	}

	// 4. Controlled restart -> flushes ledger seamlessly with 0 gap_count!
	_, err = sup.HandleRPC(M{"action": "restart", "request_id": "njob_restart01"})
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	snap, ok := sup.ledger.Snapshot()
	if !ok || snap.Quality.Gaps != 0 || len(snap.Inbounds) != 1 || snap.Inbounds[0].Upload != "19" {
		t.Fatalf("expected seamless zero-gap ledger across controlled reload, got ok=%v snap=%+v", ok, snap)
	}

	// 5. Failed reload automatically rolls back to working instance!
	err = sup.applyNewConfigBytes([]byte(`{"invalid_trigger":true}`))
	if err == nil || !sup.isRunning() {
		t.Fatalf("expected reload error with automatic rollback keeping instance running, err=%v running=%v", err, sup.isRunning())
	}

	// 6. Auto-registration and telemetry push
	delay, err := sup.PushTelemetryOnce(context.Background())
	if err != nil || !registered.Load() || telemetryCount.Load() != 1 {
		t.Fatalf("telemetry push failed: err=%v registered=%v count=%d", err, registered.Load(), telemetryCount.Load())
	}
	if delay > 2*time.Second {
		t.Fatalf("expected fast live interval when live_subscribers>0, got %v", delay)
	}
}
