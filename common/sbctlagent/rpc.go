package sbctlagent

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	identityRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,79}$`)
	hashRE     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type RPCFault struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RPCFault) Error() string { return e.Code + ": " + e.Message }

func rpcFail(code, msg string) error { return &RPCFault{Code: code, Message: msg} }

type Endpoint struct {
	Protocol  string   `json:"protocol"`
	Tag       string   `json:"tag"`
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	SNI       string   `json:"sni"`
	ALPN      []string `json:"alpn"`
	InboundID string   `json:"inbound_id,omitempty"`
}

type Credential struct {
	UserID       string  `json:"user_id"`
	Protocol     string  `json:"protocol"`
	CredentialID string  `json:"credential_id"`
	Generation   int64   `json:"generation"`
	Password     string  `json:"password"`
	UUID         *string `json:"uuid"`
	ExternalSeq  int64   `json:"external_sync_seq,omitempty"`
	InboundID    string  `json:"inbound_id,omitempty"`
}

func (c Credential) authFingerprint() string {
	s := c.Password
	if c.Protocol == "tuic" && c.UUID != nil {
		s = *c.UUID
	}
	return sha256Hex([]byte(c.Protocol + ":" + s))
}

func (c Credential) Fingerprint() string {
	fp := c.authFingerprint()
	if c.ExternalSeq > 0 {
		return digestValue(M{"authentication": fp, "credential_id": c.CredentialID, "generation": c.Generation, "external_sync_seq": c.ExternalSeq})
	}
	return fp
}

type NodeRequest struct {
	SchemaVersion int          `json:"schema_version"`
	NodeID        string       `json:"node_id"`
	RequestID     string       `json:"request_id"`
	NodeRevision  int64        `json:"node_revision"`
	TemplateHash  string       `json:"template_hash"`
	EngineBuildID string       `json:"engine_build_id"`
	Users         []Credential `json:"users"`
	Revoked       []string     `json:"revoked_credentials"`
	PayloadHash   string       `json:"payload_hash"`
	Retirement    string       `json:"retiring_inbound_id,omitempty"`
	RetirementJob string       `json:"retirement_job_id,omitempty"`
}

func (r NodeRequest) VerifyHash() error {
	m, err := decodeObject(canonicalBytes(r))
	if err != nil {
		return rpcFail("REQUEST_INVALID", "请求解码失败")
	}
	delete(m, "payload_hash")
	if r.PayloadHash != digestValue(m) {
		return rpcFail("HASH_MISMATCH", "请求摘要不匹配")
	}
	return nil
}

type RequestRecord struct {
	ID           string      `json:"id"`
	Revision     int64       `json:"revision"`
	PayloadHash  string      `json:"payload_hash"`
	State        string      `json:"state"`
	AcceptedAt   string      `json:"accepted_at"`
	AppliedAt    string      `json:"applied_at,omitempty"`
	VerifiedAt   string      `json:"verified_at,omitempty"`
	ConfigHash   string      `json:"config_hash,omitempty"`
	ErrorCode    *string     `json:"error_code"`
	AppliedEpoch string      `json:"applied_epoch,omitempty"`
	Document     NodeRequest `json:"document"`
}

func (r RequestRecord) Receipt() M {
	out := M{
		"id":            r.ID,
		"revision":      r.Revision,
		"payload_hash":  r.PayloadHash,
		"state":         r.State,
		"accepted_at":   r.AcceptedAt,
		"applied_at":    nilIfEmpty(r.AppliedAt),
		"verified_at":   nilIfEmpty(r.VerifiedAt),
		"config_hash":   nilIfEmpty(r.ConfigHash),
		"error_code":    r.ErrorCode,
		"applied_epoch": nilIfEmpty(r.AppliedEpoch),
	}
	return out
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type MaintenanceReceipt struct {
	InputHash string `json:"input_hash"`
	Result    M      `json:"result"`
}

type nodeStateDisk struct {
	NodeID               string                        `json:"node_id"`
	TemplateHash         string                        `json:"template_hash"`
	Endpoints            []Endpoint                    `json:"endpoints"`
	Revoked              map[string]bool               `json:"revoked"`
	RetiringInbounds     map[string]string             `json:"retiring_inbounds"`
	LatestRequest        *RequestRecord                `json:"latest_request,omitempty"`
	DisabledInbounds     []M                           `json:"disabled_inbounds,omitempty"`
	DisabledInboundIDs   map[string]string             `json:"disabled_inbound_ids,omitempty"`
	DisabledSubEndpoints map[string]Endpoint           `json:"disabled_sub_endpoints,omitempty"`
	MaintenanceReceipts  map[string]MaintenanceReceipt `json:"maintenance_receipts,omitempty"`
	ConfigEventSeq       int64                         `json:"config_event_seq"`
	SemanticHash         string                        `json:"semantic_hash"`
	AdoptedHash          string                        `json:"adopted_hash"`
	PendingSync          bool                          `json:"pending_sync"`
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func intVal(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func boolVal(v any) bool { b, _ := v.(bool); return b }

func mapVal(v any) M {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return M{}
}

func sliceVal(v any) []any {
	if s, ok := v.([]any); ok && s != nil {
		return s
	}
	return []any{}
}

func validStatTag(s string) bool {
	if s == "" || len(s) > 256 || strings.Contains(s, ">>>") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func normalizeEndpoints(eps []Endpoint) []Endpoint {
	out := make([]Endpoint, len(eps))
	copy(out, eps)
	for i := range out {
		if out[i].InboundID == "" {
			out[i].InboundID = legacyInboundID(out[i].Protocol, out[i].Tag)
		}
		if len(out[i].ALPN) == 0 {
			out[i].ALPN = []string{"h3"}
		}
	}
	return out
}

func configureStatisticsConfig(cfg M) error {
	used := map[string]bool{}
	inbounds := sliceVal(cfg["inbounds"])
	for _, raw := range inbounds {
		tag := strVal(mapVal(raw)["tag"])
		if tag != "" {
			if !validStatTag(tag) || used[tag] {
				return rpcFail("STATS_TAG", "入口标签无效或重复")
			}
			used[tag] = true
		}
	}
	for idx, raw := range inbounds {
		in := mapVal(raw)
		if strVal(in["tag"]) == "" {
			tag := fmt.Sprintf("sbctl-in-%s-%d", strVal(in["type"]), intVal(in["listen_port"]))
			if used[tag] {
				tag += fmt.Sprintf("-%d", idx+1)
			}
			in["tag"] = tag
			used[tag] = true
		}
		t := strVal(in["type"])
		if t == "vmess" || t == "vless" || t == "trojan" || t == "shadowsocks" || t == "hysteria2" || t == "tuic" || t == "anytls" {
			for n, ru := range sliceVal(in["users"]) {
				u := mapVal(ru)
				if strVal(u["name"]) == "" {
					u["name"] = fmt.Sprintf("sbctl-local-%s-%d", strVal(in["tag"]), n+1)
				}
			}
		}
	}
	return nil
}

func buildManifest(cfg M, state nodeStateDisk) ManifestSpec {
	var managedUsers []string
	if state.LatestRequest != nil {
		for _, u := range state.LatestRequest.Document.Users {
			managedUsers = append(managedUsers, u.UserID)
		}
	}
	excluded := map[string]bool{"sys_probe": true}
	for _, u := range managedUsers {
		excluded[u] = true
	}
	epID := map[string]string{}
	for _, ep := range state.Endpoints {
		epID[ep.Tag] = ep.InboundID
	}
	for tag, id := range state.DisabledInboundIDs {
		if epID[tag] == "" {
			epID[tag] = id
		}
	}
	inboundsRaw := sliceVal(cfg["inbounds"])
	spec := ManifestSpec{TotalInbounds: len(inboundsRaw), ManagedUsers: managedUsers}
	outSeen := map[string]bool{}
	for _, raw := range sliceVal(cfg["outbounds"]) {
		tag := strVal(mapVal(raw)["tag"])
		if tag != "" && !outSeen[tag] {
			outSeen[tag] = true
			spec.Outbounds = append(spec.Outbounds, tag)
		}
	}
	sort.Strings(spec.Outbounds)
	userSeen := map[string]bool{}
	for _, raw := range inboundsRaw {
		in := mapVal(raw)
		tag := strVal(in["tag"])
		proto := strVal(in["type"])
		if tag != "" {
			id := epID[tag]
			if id == "" {
				id = legacyInboundID(proto, tag)
			}
			spec.Inbounds = append(spec.Inbounds, InboundSpec{
				Tag: tag, Protocol: proto, Port: int(intVal(in["listen_port"])), InboundID: id,
			})
		}
		for _, ru := range sliceVal(in["users"]) {
			name := strVal(mapVal(ru)["name"])
			if name != "" && !excluded[name] && !strings.HasPrefix(name, "usr_") && !userSeen[name] {
				userSeen[name] = true
				spec.LocalUsers = append(spec.LocalUsers, name)
			}
		}
	}
	sort.Strings(spec.LocalUsers)
	sort.Slice(spec.Inbounds, func(i, j int) bool { return spec.Inbounds[i].Tag < spec.Inbounds[j].Tag })
	return spec
}

func findCredentialEndpoint(eps []Endpoint, c Credential) (Endpoint, bool) {
	var found Endpoint
	for _, ep := range eps {
		legacy := c.InboundID == "" && strings.HasPrefix(ep.InboundID, "inb_legacy_")
		if c.Protocol != ep.Protocol || (!legacy && c.InboundID != ep.InboundID) {
			continue
		}
		if found.InboundID != "" {
			return Endpoint{}, false
		}
		found = ep
	}
	return found, found.InboundID != ""
}

func parseALPN(v any) []string {
	if s, ok := v.(string); ok && s != "" {
		return []string{s}
	}
	var out []string
	for _, it := range sliceVal(v) {
		if s := strVal(it); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"h3"}
	}
	return out
}

func (s *Supervisor) HandleRPC(v M) (M, error) {
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()

	action := strVal(v["action"])
	switch action {
	case "inspect":
		return s.rpcInspect(strVal(v["public_host"]), strVal(v["server_name"]))
	case "configure":
		return s.rpcConfigure(strVal(v["node_id"]), strVal(v["request_id"]), mapVal(v["inspection"]))
	case "diagnose":
		return s.rpcDiagnose()
	case "verify_inbounds":
		return s.rpcVerifyInbounds()
	case "status":
		return s.rpcStatus(), nil
	case "submit":
		return s.rpcSubmit(v["request"])
	case "protocols":
		return s.rpcProtocols()
	case "protocol_change":
		return s.rpcProtocolChange(strVal(v["request_id"]), mapVal(v["change"]))
	case "config":
		return s.rpcConfigView()
	case "config_change":
		return s.rpcConfigChange(strVal(v["request_id"]), mapVal(v["change"]))
	case "restart":
		return s.rpcRestart(strVal(v["request_id"]))
	case "maintenance_receipt":
		return s.rpcMaintenanceReceipt(strVal(v["request_id"]), strVal(v["input_hash"]))
	case "config_snapshot":
		return s.rpcConfigSnapshot()
	case "adopt_config":
		return s.rpcAdoptConfig(mapVal(v["adoption"]))
	default:
		return nil, rpcFail("ACTION_REJECTED", "不支持的节点动作: "+action)
	}
}

func (s *Supervisor) rpcInspect(host, serverName string) (M, error) {
	raw, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	bound := s.state.NodeID != "" && s.state.TemplateHash != ""
	primary := map[string]Endpoint{}
	for _, ep := range s.state.Endpoints {
		primary[ep.Tag] = ep
	}
	var eps []Endpoint
	managed, unmanaged := 0, 0
	for _, rv := range sliceVal(cfg["inbounds"]) {
		in := mapVal(rv)
		p := strVal(in["type"])
		tag := strVal(in["tag"])
		if bound {
			if _, ok := primary[tag]; !ok {
				continue
			}
		}
		if p != "anytls" && p != "tuic" {
			continue
		}
		if !bound && host == "" {
			for _, ru := range sliceVal(in["users"]) {
				if strings.HasPrefix(strVal(mapVal(ru)["name"]), "usr_") {
					managed++
				}
			}
			continue
		}
		tlsObj := mapVal(in["tls"])
		ep := Endpoint{
			Protocol: p, Tag: tag, Server: host,
			Port: int(intVal(in["listen_port"])),
			SNI:  strVal(tlsObj["server_name"]),
			ALPN: parseALPN(tlsObj["alpn"]),
		}
		if old, ok := primary[tag]; ok {
			ep.InboundID = old.InboundID
			if ep.Server == "" {
				ep.Server = old.Server
			}
			if ep.SNI == "" {
				ep.SNI = old.SNI
			}
		}
		if ep.InboundID == "" {
			ep.InboundID = legacyInboundID(ep.Protocol, ep.Tag)
		}
		if serverName != "" {
			ep.SNI = serverName
		}
		if ep.SNI == "" {
			ep.SNI = ep.Server
		}
		eps = append(eps, ep)
		for _, ru := range sliceVal(in["users"]) {
			name := strVal(mapVal(ru)["name"])
			if strings.HasPrefix(name, "sys_") {
				continue
			}
			if strings.HasPrefix(name, "usr_") {
				managed++
			} else {
				unmanaged++
			}
		}
	}
	eps = normalizeEndpoints(eps)
	out := M{
		"container":           s.containerLabel(),
		"config_dir":          filepath.Dir(s.configPath),
		"image":               "sing-box:" + s.version,
		"engine_build_id":     s.buildID,
		"config_hash":         sha256Hex(raw),
		"compose_hash":        sha256Hex([]byte("embedded-agent")),
		"container_id":        s.containerLabel(),
		"running":             s.isRunning(),
		"endpoints":           eps,
		"uid":                 max(1, os.Getuid()),
		"gid":                 max(1, os.Getgid()),
		"existing_node_id":    s.state.NodeID,
		"managed_credentials": managed,
		"preserved_users":     unmanaged,
		"guard_current":       true,
		"can_adopt":           s.isRunning(),
		"version":             "sing-box version " + s.version,
		"checked_at":          nowUTC(),
		"native_stats_socket": true,
		"server_name":         serverName,
		"public_host":         host,
		"impact":              "启用单容器内置控制与统计账本；支持进程内热重载与用户凭据无损热更新，无需 SSH 或宿主机守护进程。",
	}
	clone, _ := decodeObject(canonicalBytes(out))
	delete(clone, "checked_at")
	out["observation_hash"] = digestValue(clone)
	return out, nil
}

func (s *Supervisor) rpcConfigure(id, requestID string, inspection M) (M, error) {
	if !identityRE.MatchString(id) || !identityRE.MatchString(requestID) {
		return nil, rpcFail("INVALID_REQUEST", "节点或请求标识无效")
	}
	inputHash := digestValue(M{"inspection": inspection, "node_id": id})
	if saved, ok := s.state.MaintenanceReceipts[requestID]; ok {
		if saved.InputHash != inputHash {
			return nil, rpcFail("REQUEST_CONFLICT", "接管请求内容冲突")
		}
		return saved.Result, nil
	}
	var eps []Endpoint
	_ = json.Unmarshal(canonicalBytes(inspection["endpoints"]), &eps)
	host := strVal(inspection["public_host"])
	if host == "" && len(eps) > 0 {
		host = eps[0].Server
	}
	actual, err := s.rpcInspect(host, strVal(inspection["server_name"]))
	if err != nil {
		return nil, err
	}
	if strVal(actual["observation_hash"]) != strVal(inspection["observation_hash"]) {
		return nil, rpcFail("INSPECTION_CHANGED", "节点运行状态或配置已变化，请重新检查")
	}
	if s.nodeID() != id {
		return nil, rpcFail("NODE_IDENTITY", "该实例已绑定其他节点 ID")
	}
	eps = normalizeEndpoints(eps)

	known := map[string]bool{}
	var rev int64
	if s.state.LatestRequest != nil {
		rev = s.state.LatestRequest.Revision
		for _, c := range s.state.LatestRequest.Document.Users {
			known[c.UserID] = true
		}
	}

	rawBefore, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	boundTag := map[string]bool{}
	for _, ep := range eps {
		boundTag[ep.Tag] = true
	}
	if s.state.TemplateHash == "" {
		for _, rv := range sliceVal(cfg["inbounds"]) {
			in := mapVal(rv)
			if !boundTag[strVal(in["tag"])] {
				continue
			}
			p := strVal(in["type"])
			if p != "anytls" && p != "tuic" {
				continue
			}
			var preserved []any
			for _, ru := range sliceVal(in["users"]) {
				name := strVal(mapVal(ru)["name"])
				if !strings.HasPrefix(name, "usr_") && name != "sys_probe" {
					preserved = append(preserved, ru)
				}
			}
			in["users"] = preserved
		}
	}
	if err := configureStatisticsConfig(cfg); err != nil {
		return nil, err
	}
	afterBytes := append(canonicalBytes(cfg), '\n')
	tplObj, _ := decodeObject(afterBytes)
	for _, rv := range sliceVal(tplObj["inbounds"]) {
		in := mapVal(rv)
		if !boundTag[strVal(in["tag"])] {
			continue
		}
		p := strVal(in["type"])
		if p != "anytls" && p != "tuic" {
			continue
		}
		var fixed []any
		for _, ru := range sliceVal(in["users"]) {
			name := strVal(mapVal(ru)["name"])
			if !known[name] && name != "sys_probe" {
				fixed = append(fixed, ru)
			}
		}
		in["users"] = fixed
	}
	tplBytes := append(canonicalBytes(tplObj), '\n')
	tplHash := sha256Hex(tplBytes)

	if sha256Hex(rawBefore) != sha256Hex(afterBytes) {
		if err := s.applyNewConfigBytes(afterBytes); err != nil {
			return nil, err
		}
	}
	if err := atomicWriteFile(s.templatePath(), tplBytes, 0600); err != nil {
		return nil, rpcFail("IO_ERROR", err.Error())
	}
	s.state.NodeID = id
	s.state.TemplateHash = tplHash
	s.state.Endpoints = eps
	s.recordControlledLocked(cfg)
	if s.state.MaintenanceReceipts == nil {
		s.state.MaintenanceReceipts = map[string]MaintenanceReceipt{}
	}
	_ = s.ledger.BindNodeID(id)
	_ = s.flushStatsLocked(false)

	rt := s.runtimeInfoLocked(rev)
	res := M{
		"node_id":            id,
		"container":          s.containerLabel(),
		"image":              "sing-box:" + s.version,
		"engine_build_id":    s.buildID,
		"config_dir":         filepath.Dir(s.configPath),
		"template_hash":      tplHash,
		"endpoints":          eps,
		"runtime":            rt,
		"checked_at":         nowUTC(),
		"ready":              true,
		"version":            "sing-box version " + s.version,
		"probe_verification": M{"status": "not_run", "message": "代理拨测为独立诊断操作"},
	}
	s.state.MaintenanceReceipts[requestID] = MaintenanceReceipt{InputHash: inputHash, Result: res}
	s.pruneMaintenanceReceiptsLocked()
	_ = s.saveStateLocked()
	return res, nil
}

func (s *Supervisor) rpcDiagnose() (M, error) {
	raw, _, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	diskHash := sha256Hex(raw)
	activeHash := s.activeConfigHash()
	running := s.isRunning()
	ok := running && diskHash == activeHash
	var rev int64
	if s.state.LatestRequest != nil {
		rev = s.state.LatestRequest.Revision
	}
	checks := []M{
		{"name": "管理通道", "status": "passed", "ok": true, "message": "单容器内置控制通道在线"},
		{"name": "运行绑定", "status": map[bool]string{true: "passed", false: "failed"}[ok], "ok": ok, "message": map[bool]string{true: "内核实例与活动配置一致", false: "内核实例未运行或存在未重载修改"}[ok]},
	}
	return M{
		"node_id":         s.nodeID(),
		"container":       s.containerLabel(),
		"image":           "sing-box:" + s.version,
		"engine_build_id": s.buildID,
		"config_dir":      filepath.Dir(s.configPath),
		"checked_at":      nowUTC(),
		"ready":           ok,
		"runtime":         s.runtimeInfoLocked(rev),
		"checks":          checks,
	}, nil
}

func (s *Supervisor) rpcVerifyInbounds() (M, error) {
	raw, active, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	cfgHash := sha256Hex(raw)
	if !s.isRunning() || s.activeConfigHash() != cfgHash {
		return nil, rpcFail("RUNTIME_BINDING", "运行配置与磁盘配置不一致")
	}
	eps := normalizeEndpoints(s.state.Endpoints)
	if len(eps) == 0 {
		return M{
			"node_id":         s.nodeID(),
			"template_hash":   s.state.TemplateHash,
			"endpoints":       eps,
			"protocol_status": "not_applicable",
			"probe_verification": M{
				"status":         "not_applicable",
				"template_hash":  s.state.TemplateHash,
				"endpoints_hash": digestValue(eps),
				"runtime_epoch":  s.activeEpoch(),
				"config_hash":    cfgHash,
				"checked_at":     nowUTC(),
			},
		}, nil
	}
	checks := make([]M, 0, len(eps))
	for _, ep := range eps {
		in := findInboundByTag(active, ep.Tag)
		if in == nil || strVal(in["type"]) != ep.Protocol || int(intVal(in["listen_port"])) != ep.Port {
			return nil, rpcFail("PROBE_FAILED", fmt.Sprintf("活动配置缺少入口 %s 或端口不一致", ep.Tag))
		}
		item := M{"inbound_id": ep.InboundID, "tag": ep.Tag, "protocol": ep.Protocol, "port": ep.Port, "ok": true}
		if ep.Protocol == "anytls" {
			target := net.JoinHostPort("127.0.0.1", strconv.Itoa(ep.Port))
			conn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", target, &tls.Config{
				ServerName:         ep.SNI,
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: ep.SNI == "",
			})
			if dialErr != nil {
				return nil, rpcFail("PROBE_FAILED", fmt.Sprintf("入口 %s TLS 握手失败: %v", ep.Tag, dialErr))
			}
			certs := conn.ConnectionState().PeerCertificates
			_ = conn.Close()
			if len(certs) > 0 {
				item["cert_not_after"] = certs[0].NotAfter.UTC().Format(time.RFC3339)
			}
		}
		checks = append(checks, item)
	}
	proof := M{
		"status":         "passed",
		"template_hash":  s.state.TemplateHash,
		"endpoints_hash": digestValue(eps),
		"runtime_epoch":  s.activeEpoch(),
		"config_hash":    cfgHash,
		"checked_at":     nowUTC(),
		"endpoints":      checks,
	}
	return M{
		"node_id":            s.nodeID(),
		"template_hash":      s.state.TemplateHash,
		"endpoints":          eps,
		"protocol_status":    "passed",
		"probe_verification": proof,
	}, nil
}

func (s *Supervisor) rpcStatus() M {
	var latest any
	if s.state.LatestRequest != nil {
		latest = s.state.LatestRequest.Receipt()
	}
	return M{"node_id": s.nodeID(), "latest": latest}
}

func (s *Supervisor) rpcSubmit(rawReq any) (M, error) {
	var r NodeRequest
	if err := json.Unmarshal(canonicalBytes(rawReq), &r); err != nil {
		return nil, rpcFail("REQUEST_INVALID", "授权请求格式无效")
	}
	if err := r.VerifyHash(); err != nil {
		return nil, err
	}
	if r.NodeID != s.nodeID() || r.TemplateHash != s.state.TemplateHash || (r.EngineBuildID != "" && r.EngineBuildID != s.buildID) {
		return nil, rpcFail("NODE_BINDING", "节点、模板或内核构建不匹配")
	}
	if s.observedExternalChangeLocked() {
		return nil, rpcFail("CONFIG_SYNC_PENDING", "节点配置已被外部修改，等待主控同步后再执行授权")
	}
	if s.state.LatestRequest != nil {
		old := s.state.LatestRequest
		if old.ID == r.RequestID || old.Revision == r.NodeRevision {
			if old.ID != r.RequestID || old.PayloadHash != r.PayloadHash {
				return nil, rpcFail("REQUEST_CONFLICT", "请求标识或版本内容冲突")
			}
			return M{"node_id": s.nodeID(), "latest": old.Receipt()}, nil
		}
		if r.NodeRevision < old.Revision {
			return nil, rpcFail("STALE_REVISION", "请求早于已接受安全版本")
		}
	}
	if s.state.Revoked == nil {
		s.state.Revoked = map[string]bool{}
	}
	if s.state.RetiringInbounds == nil {
		s.state.RetiringInbounds = map[string]string{}
	}
	if r.Retirement != "" {
		found := false
		for _, ep := range s.state.Endpoints {
			found = found || ep.InboundID == r.Retirement
		}
		if !found {
			return nil, rpcFail("CREDENTIAL_BINDING", "退役请求指向未登记入口")
		}
		if job, exists := s.state.RetiringInbounds[r.Retirement]; exists && job != r.RetirementJob {
			return nil, rpcFail("RETIREMENT_PENDING", "入口已由另一个退役请求锁定")
		}
	}
	eps := normalizeEndpoints(s.state.Endpoints)
	for _, c := range r.Users {
		if !strings.HasPrefix(c.UserID, "usr_") {
			return nil, rpcFail("USER_IDENTITY", "受管用户必须使用中心永久身份")
		}
		ep, ok := findCredentialEndpoint(eps, c)
		if !ok || ep.InboundID == r.Retirement {
			return nil, rpcFail("CREDENTIAL_BINDING", "凭据未绑定到有效入口")
		}
		if _, retiring := s.state.RetiringInbounds[ep.InboundID]; retiring {
			return nil, rpcFail("RETIREMENT_PENDING", "入口正在退役，拒绝恢复用户凭据")
		}
	}
	reqRevoked := map[string]bool{}
	for _, fp := range r.Revoked {
		reqRevoked[fp] = true
	}
	for fp := range s.state.Revoked {
		if !reqRevoked[fp] {
			return nil, rpcFail("REVOKED_CREDENTIAL", "请求遗漏撤销记录")
		}
	}
	for _, c := range r.Users {
		if reqRevoked[c.Fingerprint()] {
			return nil, rpcFail("REVOKED_CREDENTIAL", "请求包含已撤销凭据")
		}
	}

	rendered, err := s.renderRequestLocked(r)
	if err != nil {
		return nil, err
	}
	if err := s.applyAuthorizationConfigLocked(eps, rendered); err != nil {
		return nil, err
	}

	cfgHash := sha256Hex(rendered)
	now := nowUTC()
	for _, fp := range r.Revoked {
		s.state.Revoked[fp] = true
	}
	if r.Retirement != "" {
		s.state.RetiringInbounds[r.Retirement] = r.RetirementJob
	}
	rec := &RequestRecord{
		ID:           r.RequestID,
		Revision:     r.NodeRevision,
		PayloadHash:  r.PayloadHash,
		State:        "verified",
		AcceptedAt:   now,
		AppliedAt:    now,
		VerifiedAt:   now,
		ConfigHash:   cfgHash,
		AppliedEpoch: s.activeEpoch(),
		Document:     r,
	}
	s.state.LatestRequest = rec
	cfgObj, _ := decodeObject(rendered)
	s.recordControlledLocked(cfgObj)
	_ = s.saveStateLocked()
	return M{"node_id": s.nodeID(), "latest": rec.Receipt()}, nil
}

func (s *Supervisor) renderRequestLocked(r NodeRequest) ([]byte, error) {
	tplBytes, err := os.ReadFile(s.templatePath())
	if err != nil {
		return nil, rpcFail("TEMPLATE_MISMATCH", "读取节点配置模板失败")
	}
	if sha256Hex(tplBytes) != s.state.TemplateHash {
		return nil, rpcFail("TEMPLATE_MISMATCH", "本机模板摘要不匹配")
	}
	t, err := decodeObject(tplBytes)
	if err != nil {
		return nil, rpcFail("TEMPLATE_INVALID", "模板 JSON 无效")
	}
	eps := normalizeEndpoints(s.state.Endpoints)
	tags := map[string]Endpoint{}
	for _, ep := range eps {
		tags[ep.Tag] = ep
	}
	usersByTag := map[string][]Credential{}
	for _, c := range r.Users {
		ep, ok := findCredentialEndpoint(eps, c)
		if !ok {
			return nil, rpcFail("CREDENTIAL_BINDING", "凭据未绑定到有效入口")
		}
		usersByTag[ep.Tag] = append(usersByTag[ep.Tag], c)
	}
	found := map[string]bool{}
	for _, rv := range sliceVal(t["inbounds"]) {
		in := mapVal(rv)
		tag := strVal(in["tag"])
		ep, ok := tags[tag]
		if !ok {
			continue
		}
		if strVal(in["type"]) != ep.Protocol || found[tag] {
			return nil, rpcFail("TEMPLATE_INVALID", "受管入口类型或标签不匹配")
		}
		found[tag] = true
		var users []M
		for _, rf := range sliceVal(in["users"]) {
			m := mapVal(rf)
			if strVal(m["name"]) == "sys_probe" {
				continue
			}
			users = append(users, m)
		}
		for _, c := range usersByTag[tag] {
			for _, fixed := range users {
				if strVal(fixed["password"]) == c.Password || (c.Protocol == "tuic" && c.UUID != nil && strVal(fixed["uuid"]) == *c.UUID) {
					return nil, rpcFail("CREDENTIAL_CONFLICT", "凭据与节点保留用户冲突")
				}
			}
			u := M{"name": c.UserID, "password": c.Password}
			if c.Protocol == "tuic" && c.UUID != nil {
				u["uuid"] = *c.UUID
			}
			users = append(users, u)
		}
		in["users"] = users
	}
	if len(found) != len(tags) {
		return nil, rpcFail("TEMPLATE_INVALID", "模板缺少已登记入口")
	}
	if err := configureStatisticsConfig(t); err != nil {
		return nil, err
	}
	return append(canonicalBytes(t), '\n'), nil
}

func findInboundByTag(cfg M, tag string) M {
	for _, rv := range sliceVal(cfg["inbounds"]) {
		m := mapVal(rv)
		if strVal(m["tag"]) == tag {
			return m
		}
	}
	return nil
}

func referencedInboundTag(value any, tag string) bool {
	switch v := value.(type) {
	case map[string]any:
		for k, x := range v {
			if k == "inbound" {
				switch sel := x.(type) {
				case string:
					if sel == tag {
						return true
					}
				case []any:
					for _, s := range sel {
						if strVal(s) == tag {
							return true
						}
					}
				}
			}
			if referencedInboundTag(x, tag) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if referencedInboundTag(x, tag) {
				return true
			}
		}
	}
	return false
}

func (s *Supervisor) buildCatalogLocked(cfg M) M {
	eps := normalizeEndpoints(s.state.Endpoints)
	managed := map[string]string{}
	for _, ep := range eps {
		managed[ep.Tag] = ep.InboundID
	}
	disabledObj := M{
		"inbounds":               s.state.DisabledInbounds,
		"inbound_ids":            s.state.DisabledInboundIDs,
		"subscription_endpoints": s.state.DisabledSubEndpoints,
	}
	cfgWithoutInbounds, _ := decodeObject(canonicalBytes(cfg))
	delete(cfgWithoutInbounds, "inbounds")

	var items []M
	appendList := func(list []any, enabled bool) {
		for _, rv := range list {
			in := mapVal(rv)
			tag := strVal(in["tag"])
			if tag == "" {
				continue
			}
			inboundID := managed[tag]
			if inboundID == "" && s.state.DisabledInboundIDs != nil {
				inboundID = s.state.DisabledInboundIDs[tag]
			}
			if inboundID == "" {
				inboundID = legacyInboundID(strVal(in["type"]), tag)
			}
			items = append(items, M{
				"inbound_id":  inboundID,
				"referenced":  referencedInboundTag(cfgWithoutInbounds, tag),
				"tag":         tag,
				"protocol":    strVal(in["type"]),
				"listen":      strVal(in["listen"]),
				"port":        int(intVal(in["listen_port"])),
				"enabled":     enabled,
				"managed":     managed[tag] != "",
				"user_count":  len(sliceVal(in["users"])),
				"tls":         boolVal(mapVal(in["tls"])["enabled"]),
				"method":      strVal(in["method"]),
				"target_host": strVal(in["override_address"]),
				"target_port": int(intVal(in["override_port"])),
			})
		}
	}
	appendList(sliceVal(cfg["inbounds"]), true)
	var disSlice []any
	for _, d := range s.state.DisabledInbounds {
		disSlice = append(disSlice, d)
	}
	appendList(disSlice, false)
	sort.Slice(items, func(i, j int) bool { return strVal(items[i]["tag"]) < strVal(items[j]["tag"]) })
	if items == nil {
		items = []M{}
	}
	catHash := digestValue(M{
		"config":        cfg,
		"disabled":      disabledObj,
		"template_hash": s.state.TemplateHash,
		"endpoints":     eps,
	})
	return M{
		"node_id":    s.nodeID(),
		"hash":       catHash,
		"checked_at": nowUTC(),
		"items":      items,
	}
}

func (s *Supervisor) rpcProtocols() (M, error) {
	_, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	return s.buildCatalogLocked(cfg), nil
}

func (s *Supervisor) rpcProtocolChange(requestID string, change M) (M, error) {
	inputHash := digestValue(change)
	if saved, ok := s.state.MaintenanceReceipts[requestID]; ok {
		if saved.InputHash != inputHash {
			return nil, rpcFail("REQUEST_CONFLICT", "协议维护请求内容冲突")
		}
		return saved.Result, nil
	}
	_, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	tplBytes, err := os.ReadFile(s.templatePath())
	if err != nil {
		return nil, rpcFail("TEMPLATE_MISMATCH", "读取节点模板失败")
	}
	tpl, err := decodeObject(tplBytes)
	if err != nil {
		return nil, rpcFail("TEMPLATE_INVALID", "节点模板无效")
	}
	retireID := strVal(change["retire_id"])
	if retireID == "" && strVal(s.buildCatalogLocked(cfg)["hash"]) != strVal(change["base_hash"]) {
		return nil, rpcFail("PROTOCOL_CHANGED", "协议配置已变化，请重新读取后操作")
	}

	action := strVal(change["action"])
	tag := strVal(change["tag"])
	newTag := strVal(change["new_tag"])
	if newTag == "" {
		newTag = tag
	}
	eps := append([]Endpoint(nil), normalizeEndpoints(s.state.Endpoints)...)
	disInbounds := append([]M(nil), s.state.DisabledInbounds...)
	disIDs := map[string]string{}
	for k, v := range s.state.DisabledInboundIDs {
		disIDs[k] = v
	}
	disSubs := map[string]Endpoint{}
	for k, v := range s.state.DisabledSubEndpoints {
		disSubs[k] = v
	}

	var retirementEvidence M
	switch action {
	case "create":
		srcTag := strVal(change["source_tag"])
		src := findInboundByTag(cfg, srcTag)
		if src == nil {
			for _, d := range disInbounds {
				if strVal(d["tag"]) == srcTag {
					src = d
					break
				}
			}
		}
		if src == nil {
			return nil, rpcFail("NOT_FOUND", "未找到源协议模板")
		}
		if findInboundByTag(cfg, tag) != nil {
			return nil, rpcFail("TAG_CONFLICT", "入口标签已存在")
		}
		cloned, _ := decodeObject(canonicalBytes(src))
		cloned["tag"] = tag
		cloned["listen"] = strVal(change["listen"])
		cloned["listen_port"] = int(intVal(change["port"]))
		if th := strVal(change["target_host"]); th != "" {
			cloned["override_address"] = th
			cloned["override_port"] = int(intVal(change["target_port"]))
		}
		p := strVal(cloned["type"])
		user := M{"name": strVal(change["username"]), "password": strVal(change["password"])}
		if p == "tuic" || p == "vmess" || p == "vless" {
			user["uuid"] = strVal(change["uuid"])
		}
		cloned["users"] = []M{user}
		if sn := strVal(change["server_name"]); sn != "" && cloned["tls"] != nil {
			mapVal(cloned["tls"])["server_name"] = sn
		}
		inboundID := randomID("inb")
		disIDs[tag] = inboundID
		if pub := strVal(change["subscription_host"]); pub != "" && (p == "anytls" || p == "tuic") {
			tlsObj := mapVal(cloned["tls"])
			sni := strVal(tlsObj["server_name"])
			if sni == "" {
				sni = pub
			}
			eps = append(eps, Endpoint{Protocol: p, Tag: tag, Server: pub, Port: int(intVal(change["port"])), SNI: sni, ALPN: parseALPN(tlsObj["alpn"]), InboundID: inboundID})
		}
		cfg["inbounds"] = append(sliceVal(cfg["inbounds"]), cloned)
		tplClone, _ := decodeObject(canonicalBytes(cloned))
		tpl["inbounds"] = append(sliceVal(tpl["inbounds"]), tplClone)

	case "edit":
		for _, doc := range []M{cfg, tpl} {
			in := findInboundByTag(doc, tag)
			if in == nil {
				return nil, rpcFail("NOT_FOUND", "入口不存在")
			}
			in["tag"] = newTag
			in["listen"] = strVal(change["listen"])
			in["listen_port"] = int(intVal(change["port"]))
			if th := strVal(change["target_host"]); th != "" {
				in["override_address"] = th
				in["override_port"] = int(intVal(change["target_port"]))
			}
			if sn := strVal(change["server_name"]); sn != "" && in["tls"] != nil {
				mapVal(in["tls"])["server_name"] = sn
			}
		}
		if id, ok := disIDs[tag]; ok && newTag != tag {
			delete(disIDs, tag)
			disIDs[newTag] = id
		}
		for i := range eps {
			if eps[i].Tag == tag {
				eps[i].Tag = newTag
				eps[i].Port = int(intVal(change["port"]))
				if pub := strVal(change["subscription_host"]); pub != "" {
					eps[i].Server = pub
				}
				if sn := strVal(change["server_name"]); sn != "" {
					eps[i].SNI = sn
				}
			}
		}

	case "disable", "delete":
		in := findInboundByTag(cfg, tag)
		if in == nil && action == "delete" {
			var kept []M
			for _, d := range disInbounds {
				if strVal(d["tag"]) != tag {
					kept = append(kept, d)
				}
			}
			disInbounds = kept
			delete(disIDs, tag)
			delete(disSubs, tag)
		} else if in != nil {
			cfgCopy, _ := decodeObject(canonicalBytes(cfg))
			delete(cfgCopy, "inbounds")
			if referencedInboundTag(cfgCopy, tag) {
				return nil, rpcFail("INBOUND_REFERENCED", "该入口仍被路由规则引用，无法停用或删除")
			}
			for _, ep := range eps {
				if ep.Tag == tag && retireID != ep.InboundID {
					return nil, rpcFail("PROTOCOL_REQUIRED", "受管授权入口需通过退役流程停用或删除")
				}
			}
			if action == "disable" {
				savedIn, _ := decodeObject(canonicalBytes(in))
				var cleanUsers []any
				for _, ru := range sliceVal(savedIn["users"]) {
					if !strings.HasPrefix(strVal(mapVal(ru)["name"]), "usr_") {
						cleanUsers = append(cleanUsers, ru)
					}
				}
				savedIn["users"] = cleanUsers
				disInbounds = append(disInbounds, savedIn)
			} else {
				delete(disIDs, tag)
				delete(disSubs, tag)
			}
			for _, doc := range []M{cfg, tpl} {
				var out []any
				for _, rv := range sliceVal(doc["inbounds"]) {
					if strVal(mapVal(rv)["tag"]) != tag {
						out = append(out, rv)
					}
				}
				doc["inbounds"] = out
			}
			var nextEps []Endpoint
			for _, ep := range eps {
				if ep.Tag == tag {
					if action == "disable" {
						disSubs[tag] = ep
						disIDs[tag] = ep.InboundID
					}
					continue
				}
				nextEps = append(nextEps, ep)
			}
			eps = nextEps
		}
		if retireID != "" {
			var rev int64
			if s.state.LatestRequest != nil {
				rev = s.state.LatestRequest.Revision
			}
			retirementEvidence = M{
				"inbound_id":    retireID,
				"tag":           tag,
				"action":        action,
				"request_id":    requestID,
				"node_revision": rev,
			}
		}

	case "enable":
		var target M
		var kept []M
		for _, d := range disInbounds {
			if strVal(d["tag"]) == tag {
				target = d
			} else {
				kept = append(kept, d)
			}
		}
		if target == nil {
			return nil, rpcFail("NOT_FOUND", "未找到已停用入口")
		}
		disInbounds = kept
		cfg["inbounds"] = append(sliceVal(cfg["inbounds"]), target)
		tplCopy, _ := decodeObject(canonicalBytes(target))
		tpl["inbounds"] = append(sliceVal(tpl["inbounds"]), tplCopy)
		if subEp, ok := disSubs[tag]; ok {
			delete(disSubs, tag)
			eps = append(eps, subEp)
		}
	default:
		return nil, rpcFail("INVALID_REQUEST", "未知协议变更动作")
	}

	if err := configureStatisticsConfig(cfg); err != nil {
		return nil, err
	}
	if err := configureStatisticsConfig(tpl); err != nil {
		return nil, err
	}
	newCfgBytes := append(canonicalBytes(cfg), '\n')
	newTplBytes := append(canonicalBytes(tpl), '\n')
	if err := s.applyNewConfigBytes(newCfgBytes); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(s.templatePath(), newTplBytes, 0600); err != nil {
		return nil, rpcFail("IO_ERROR", err.Error())
	}
	s.state.Endpoints = normalizeEndpoints(eps)
	s.state.TemplateHash = sha256Hex(newTplBytes)
	s.state.DisabledInbounds = disInbounds
	s.state.DisabledInboundIDs = disIDs
	s.state.DisabledSubEndpoints = disSubs
	if retireID != "" {
		delete(s.state.RetiringInbounds, retireID)
	}
	s.recordControlledLocked(cfg)

	cfgHash := sha256Hex(newCfgBytes)
	if retirementEvidence != nil {
		retirementEvidence["config_hash"] = cfgHash
		retirementEvidence["runtime_epoch"] = s.activeEpoch()
	}
	res := s.maintenanceResultLocked(cfg, cfgHash)
	if retirementEvidence != nil {
		res["retirement"] = retirementEvidence
	}
	if s.state.MaintenanceReceipts == nil {
		s.state.MaintenanceReceipts = map[string]MaintenanceReceipt{}
	}
	s.state.MaintenanceReceipts[requestID] = MaintenanceReceipt{InputHash: inputHash, Result: res}
	s.pruneMaintenanceReceiptsLocked()
	_ = s.saveStateLocked()
	return res, nil
}

var replaceableSections = []string{"log", "dns", "ntp", "route"}

func buildConfigView(nodeID string, cfg M) M {
	sections := M{}
	for _, name := range replaceableSections {
		sections[name] = mapVal(cfg[name])
	}
	var outbounds []M
	for _, raw := range sliceVal(cfg["outbounds"]) {
		o := mapVal(raw)
		outbounds = append(outbounds, M{"tag": strVal(o["tag"]), "type": strVal(o["type"]), "server": strVal(o["server"]), "server_port": intVal(o["server_port"])})
	}
	if outbounds == nil {
		outbounds = []M{}
	}
	var inboundTags []string
	for _, raw := range sliceVal(cfg["inbounds"]) {
		if tag := strVal(mapVal(raw)["tag"]); tag != "" {
			inboundTags = append(inboundTags, tag)
		}
	}
	if inboundTags == nil {
		inboundTags = []string{}
	}
	return M{
		"node_id":      nodeID,
		"hash":         digestValue(sections),
		"checked_at":   nowUTC(),
		"sections":     sections,
		"outbounds":    outbounds,
		"inbound_tags": inboundTags,
	}
}

func (s *Supervisor) rpcConfigView() (M, error) {
	_, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	return buildConfigView(s.nodeID(), cfg), nil
}

func (s *Supervisor) rpcConfigChange(requestID string, change M) (M, error) {
	inputHash := digestValue(change)
	if saved, ok := s.state.MaintenanceReceipts[requestID]; ok {
		if saved.InputHash != inputHash {
			return nil, rpcFail("REQUEST_CONFLICT", "配置修改回执冲突")
		}
		return saved.Result, nil
	}
	section := strVal(change["section"])
	validSec := false
	for _, sec := range replaceableSections {
		validSec = validSec || sec == section
	}
	if !validSec {
		return nil, rpcFail("INVALID_REQUEST", "不支持编辑该配置片段")
	}
	_, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	if strVal(buildConfigView(s.nodeID(), cfg)["hash"]) != strVal(change["base_hash"]) {
		return nil, rpcFail("CONFIG_CHANGED", "配置已变化，请重新读取后操作")
	}
	tplBytes, err := os.ReadFile(s.templatePath())
	if err != nil {
		return nil, rpcFail("TEMPLATE_MISMATCH", "读取节点模板失败")
	}
	tpl, err := decodeObject(tplBytes)
	if err != nil {
		return nil, rpcFail("TEMPLATE_INVALID", "节点模板无效")
	}
	content := mapVal(change["content"])
	for _, doc := range []M{cfg, tpl} {
		if len(content) == 0 {
			delete(doc, section)
		} else {
			cloned, _ := decodeObject(canonicalBytes(content))
			doc[section] = cloned
		}
	}
	newCfgBytes := append(canonicalBytes(cfg), '\n')
	newTplBytes := append(canonicalBytes(tpl), '\n')
	if err := s.applyNewConfigBytes(newCfgBytes); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(s.templatePath(), newTplBytes, 0600); err != nil {
		return nil, rpcFail("IO_ERROR", err.Error())
	}
	s.state.TemplateHash = sha256Hex(newTplBytes)
	s.recordControlledLocked(cfg)
	res := s.maintenanceResultLocked(cfg, sha256Hex(newCfgBytes))
	if s.state.MaintenanceReceipts == nil {
		s.state.MaintenanceReceipts = map[string]MaintenanceReceipt{}
	}
	s.state.MaintenanceReceipts[requestID] = MaintenanceReceipt{InputHash: inputHash, Result: res}
	s.pruneMaintenanceReceiptsLocked()
	_ = s.saveStateLocked()
	return res, nil
}

func (s *Supervisor) rpcRestart(requestID string) (M, error) {
	inputHash := digestValue(nil)
	if saved, ok := s.state.MaintenanceReceipts[requestID]; ok {
		return saved.Result, nil
	}
	raw, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	if err := s.reloadInProcessLocked(raw); err != nil {
		return nil, err
	}
	s.recordControlledLocked(cfg)
	res := s.maintenanceResultLocked(cfg, sha256Hex(raw))
	if s.state.MaintenanceReceipts == nil {
		s.state.MaintenanceReceipts = map[string]MaintenanceReceipt{}
	}
	s.state.MaintenanceReceipts[requestID] = MaintenanceReceipt{InputHash: inputHash, Result: res}
	s.pruneMaintenanceReceiptsLocked()
	_ = s.saveStateLocked()
	return res, nil
}

func (s *Supervisor) rpcMaintenanceReceipt(requestID, inputHash string) (M, error) {
	if saved, ok := s.state.MaintenanceReceipts[requestID]; ok {
		if inputHash != "" && saved.InputHash != inputHash {
			return nil, rpcFail("REQUEST_CONFLICT", "维护回执摘要不匹配")
		}
		return M{"state": "completed", "result": saved.Result}, nil
	}
	return M{"state": "none"}, nil
}

func (s *Supervisor) maintenanceResultLocked(cfg M, cfgHash string) M {
	eps := normalizeEndpoints(s.state.Endpoints)
	proof := M{
		"status":         "not_run",
		"template_hash":  s.state.TemplateHash,
		"endpoints_hash": digestValue(eps),
		"runtime_epoch":  s.activeEpoch(),
		"config_hash":    cfgHash,
		"checked_at":     nowUTC(),
	}
	if verifyRes, err := s.rpcVerifyInbounds(); err == nil {
		if p := mapVal(verifyRes["probe_verification"]); len(p) > 0 {
			proof = p
		}
	}
	return M{
		"node_id":            s.nodeID(),
		"template_hash":      s.state.TemplateHash,
		"endpoints":          eps,
		"ready":              true,
		"catalog":            s.buildCatalogLocked(cfg),
		"probe_verification": proof,
	}
}

func (s *Supervisor) pruneMaintenanceReceiptsLocked() {
	if len(s.state.MaintenanceReceipts) <= 32 {
		return
	}
	for k := range s.state.MaintenanceReceipts {
		delete(s.state.MaintenanceReceipts, k)
		if len(s.state.MaintenanceReceipts) <= 24 {
			break
		}
	}
}

func (s *Supervisor) rpcConfigSnapshot() (M, error) {
	raw, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	s.refreshObservationLocked(cfg)
	_ = s.saveStateLocked()
	cfgHash := sha256Hex(raw)
	applied := s.isRunning() && s.activeConfigHash() == cfgHash
	var rev int64
	if s.state.LatestRequest != nil {
		rev = s.state.LatestRequest.Revision
	}
	var projEndpoints []M
	for _, rv := range sliceVal(cfg["inbounds"]) {
		in := mapVal(rv)
		p := strVal(in["type"])
		if p != "anytls" && p != "tuic" {
			continue
		}
		var users []M
		for _, ru := range sliceVal(in["users"]) {
			u := mapVal(ru)
			users = append(users, M{
				"name":        strVal(u["name"]),
				"fingerprint": sha256Hex(canonicalBytes(M{"password": u["password"], "uuid": u["uuid"]})),
			})
		}
		projEndpoints = append(projEndpoints, M{"tag": strVal(in["tag"]), "protocol": p, "port": intVal(in["listen_port"]), "users": users})
	}
	if projEndpoints == nil {
		projEndpoints = []M{}
	}
	return M{
		"node_id":       s.nodeID(),
		"event_seq":     s.state.ConfigEventSeq,
		"semantic_hash": s.state.SemanticHash,
		"config_hash":   cfgHash,
		"runtime_epoch": s.activeEpoch(),
		"node_revision": rev,
		"template_hash": s.state.TemplateHash,
		"applied":       applied,
		"external":      s.observedExternalChangeLocked(),
		"config":        cfg,
		"projection":    M{"endpoints": projEndpoints},
	}, nil
}

func (s *Supervisor) rpcAdoptConfig(adoption M) (M, error) {
	var r NodeRequest
	if err := json.Unmarshal(canonicalBytes(adoption["request"]), &r); err != nil {
		return nil, rpcFail("REQUEST_INVALID", "接管请求无效")
	}
	if err := r.VerifyHash(); err != nil {
		return nil, err
	}
	raw, cfg, err := s.readDiskConfig()
	if err != nil {
		return nil, err
	}
	s.refreshObservationLocked(cfg)
	cfgHash := sha256Hex(raw)
	if !s.isRunning() || s.activeConfigHash() != cfgHash ||
		s.state.ConfigEventSeq != intVal(adoption["event_seq"]) ||
		s.state.SemanticHash != strVal(adoption["semantic_hash"]) ||
		s.activeEpoch() != strVal(adoption["runtime_epoch"]) {
		return nil, rpcFail("CONFIG_CHANGED", "节点配置或运行周期已变化，请重新同步")
	}

	nextEps, tplObj, err := projectExternalConfig(s.state.Endpoints, cfg)
	if err != nil {
		return nil, err
	}
	tplBytes := append(canonicalBytes(tplObj), '\n')
	tplHash := sha256Hex(tplBytes)
	if r.NodeID != s.nodeID() || r.TemplateHash != tplHash {
		return nil, rpcFail("NODE_BINDING", "配置接管目标不一致")
	}
	if err := atomicWriteFile(s.templatePath(), tplBytes, 0600); err != nil {
		return nil, rpcFail("IO_ERROR", err.Error())
	}
	s.state.Endpoints = nextEps
	s.state.TemplateHash = tplHash
	s.state.AdoptedHash = s.state.SemanticHash
	s.state.PendingSync = false
	if s.state.Revoked == nil {
		s.state.Revoked = map[string]bool{}
	}
	for _, fp := range r.Revoked {
		s.state.Revoked[fp] = true
	}
	now := nowUTC()
	s.state.LatestRequest = &RequestRecord{
		ID: r.RequestID, Revision: r.NodeRevision, PayloadHash: r.PayloadHash,
		State: "verified", AcceptedAt: now, AppliedAt: now, VerifiedAt: now,
		ConfigHash: cfgHash, AppliedEpoch: s.activeEpoch(), Document: r,
	}
	_ = s.saveStateLocked()
	proof := M{
		"template_hash":  tplHash,
		"endpoints_hash": digestValue(nextEps),
		"runtime_epoch":  s.activeEpoch(),
		"config_hash":    cfgHash,
		"checked_at":     now,
	}
	return M{
		"node_id":            s.nodeID(),
		"event_seq":          s.state.ConfigEventSeq,
		"semantic_hash":      s.state.SemanticHash,
		"template_hash":      tplHash,
		"endpoints":          nextEps,
		"node_revision":      r.NodeRevision,
		"request_id":         r.RequestID,
		"probe_verification": proof,
	}, nil
}

func projectExternalConfig(currentEps []Endpoint, cfg M) ([]Endpoint, M, error) {
	tpl, _ := decodeObject(canonicalBytes(cfg))
	byTag := map[string]M{}
	for _, rv := range sliceVal(tpl["inbounds"]) {
		in := mapVal(rv)
		tag := strVal(in["tag"])
		if tag == "" {
			continue
		}
		if byTag[tag] != nil {
			return nil, nil, rpcFail("BINDING_CONFLICT", "入口标签重复，暂停此节点授权")
		}
		byTag[tag] = in
	}
	eps := normalizeEndpoints(currentEps)
	claimed := map[string]bool{}
	for i := range eps {
		e := &eps[i]
		in := byTag[e.Tag]
		if in == nil || strVal(in["type"]) != e.Protocol {
			var candidates []M
			for _, cand := range byTag {
				if strVal(cand["type"]) == e.Protocol {
					candidates = append(candidates, cand)
				}
			}
			if len(candidates) != 1 {
				return nil, nil, rpcFail("BINDING_CONFLICT", "受管入口缺失或无法唯一匹配")
			}
			in = candidates[0]
			e.Tag = strVal(in["tag"])
		}
		if claimed[e.Tag] {
			return nil, nil, rpcFail("BINDING_CONFLICT", "多个入口绑定到同一标签")
		}
		claimed[e.Tag] = true
		e.Port = int(intVal(in["listen_port"]))
		tlsObj := mapVal(in["tls"])
		if sni := strVal(tlsObj["server_name"]); sni != "" {
			e.SNI = sni
		}
		if tlsObj["alpn"] != nil {
			e.ALPN = parseALPN(tlsObj["alpn"])
		}
		var kept []any
		for _, ru := range sliceVal(in["users"]) {
			name := strVal(mapVal(ru)["name"])
			if !strings.HasPrefix(name, "usr_") && name != "sys_probe" {
				kept = append(kept, ru)
			}
		}
		in["users"] = kept
	}
	return eps, tpl, nil
}

var _ = netip.ParseAddr
