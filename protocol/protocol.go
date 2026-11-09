// Package protocol is the wire contract between the upkeeper agent and the
// upkeeper.sh control plane. Both sides import it; change it only with a
// version bump and tests on both sides.
//
// M0 transport: HTTPS, agent → cloud only (outbound). JSON bodies.
//
//	POST /v1/enroll   EnrollRequest → EnrollResponse   (no auth; one-time token in body)
//	POST /v1/report   Report        → ReportAck        (Authorization: Bearer <agent token>)
//
// From M1 the agent also long-polls GET /v1/jobs for signed jobs.
package protocol

import "time"

const Version = 1

// ---- enrollment ----

type EnrollRequest struct {
	EnrollToken  string `json:"enroll_token"` // single-use, from the dashboard, expires in 1h
	Hostname     string `json:"hostname"`
	MachineID    string `json:"machine_id"` // /etc/machine-id
	AgentVersion string `json:"agent_version"`
}

type EnrollResponse struct {
	ServerID    string `json:"server_id"`
	AgentToken  string `json:"agent_token"` // long-lived; stored 0600 in /etc/upkeeper/agent.json
	ReportEvery int    `json:"report_every_seconds"`
}

// ---- report (the staleness report's raw data) ----

type Report struct {
	ProtocolVersion int       `json:"protocol_version"`
	AgentVersion    string    `json:"agent_version"`
	CollectedAt     time.Time `json:"collected_at"`
	System          System    `json:"system"`
	Packages        Packages  `json:"packages"`
	Docker          Docker    `json:"docker"`
	Projects        []Project `json:"projects"`
	Risks           []Risk    `json:"risks"`
	Items           []Item    `json:"items"`            // every pending update, classified
	Errors          []string  `json:"errors,omitempty"` // collectors that failed; never fail the whole report
}

type ReportAck struct {
	OK          bool `json:"ok"`
	ReportEvery int  `json:"report_every_seconds"`
}

type System struct {
	OSID               string   `json:"os_id"`      // ubuntu | debian
	OSVersion          string   `json:"os_version"` // 24.04 | 12
	OSCodename         string   `json:"os_codename"`
	Supported          bool     `json:"supported"`
	Arch               string   `json:"arch"`
	KernelRunning      string   `json:"kernel_running"`
	KernelInstalled    string   `json:"kernel_newest_installed"`
	RebootRequired     bool     `json:"reboot_required"`
	UptimeSeconds      int64    `json:"uptime_seconds"`
	MemTotalMB         int      `json:"mem_total_mb"`
	Disks              []Disk   `json:"disks"`
	FailedUnits        []string `json:"failed_units"`
	UnattendedUpgrades bool     `json:"unattended_upgrades_enabled"`
}

type Disk struct {
	Mount  string `json:"mount"`
	SizeMB int64  `json:"size_mb"`
	UsedMB int64  `json:"used_mb"`
}

type Packages struct {
	SecurityUpdates int        `json:"security_updates"`
	OtherUpdates    int        `json:"other_updates"`
	Held            []string   `json:"held"`
	LastAptUpdate   *time.Time `json:"last_apt_update,omitempty"`
}

type Docker struct {
	Installed      bool   `json:"installed"`
	Family         string `json:"family"` // docker-ce | docker.io | other
	EngineVersion  string `json:"engine_version"`
	ComposeVersion string `json:"compose_version"` // v2 plugin version; empty if missing
	ComposeV1      bool   `json:"compose_v1_present"`
	LatestPatch    string `json:"latest_patch_available,omitempty"` // same minor
	LatestVersion  string `json:"latest_version_available,omitempty"`
	EngineEOL      bool   `json:"engine_eol"`
}

type Project struct {
	Name     string    `json:"name"` // compose project name
	WorkDir  string    `json:"working_dir"`
	Services []Service `json:"services"`
}

type Service struct {
	Name           string   `json:"name"`
	Image          string   `json:"image"`  // as written, e.g. ghcr.io/immich-app/immich-server:v3.1.4
	Digest         string   `json:"digest"` // RepoDigest currently running
	State          string   `json:"state"`  // running | exited | restarting …
	Health         string   `json:"health"` // healthy | unhealthy | starting | none
	RestartCount   int      `json:"restart_count"`
	RestartPolicy  string   `json:"restart_policy"`
	Ports          []Port   `json:"ports"`
	HostPathMounts []string `json:"host_path_mounts"` // bind mounts / named volumes holding data
	Pinned         bool     `json:"pinned"`           // digest-pinned or label upkeeper.policy=pin
}

type Port struct {
	HostPort   int    `json:"host_port"`
	Proto      string `json:"proto"`
	TCPOpen    bool   `json:"tcp_open"`
	HTTPStatus int    `json:"http_status,omitempty"` // 0 = not HTTP / not probed
}

// ---- classification ----

type Layer string

const (
	LayerOS     Layer = "os"
	LayerKernel Layer = "kernel"
	LayerDocker Layer = "docker"
	LayerImage  Layer = "image"
)

type Decision string

const (
	Auto    Decision = "auto"    // will be applied by an automatic run (M1+)
	Flagged Decision = "flagged" // needs a supervised run
	Never   Decision = "never"   // pinned / held; reported only
)

// Item is one pending update. Reason is plain language, shown to users.
type Item struct {
	Layer    Layer    `json:"layer"`
	Subject  string   `json:"subject"` // package, "docker-ce", "kernel", or project/service
	From     string   `json:"from"`
	To       string   `json:"to"`
	Security bool     `json:"security,omitempty"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

type Severity string

const (
	Info    Severity = "info"
	Warning Severity = "warning"
	Problem Severity = "problem"
)

// Risk is something about the server that makes updating harder or riskier.
// Codes are stable identifiers: compose_v1, unattended_upgrades_conflict,
// no_restart_policy, docker_eol, os_unsupported, disk_low, reboot_pending,
// failed_units, floating_tag, coolify_host.
type Risk struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject,omitempty"`
	Message  string   `json:"message"`
}
