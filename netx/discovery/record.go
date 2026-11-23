package discovery

import (
	"fmt"
	"strings"
)

// Standard service constants for Clipdrop mDNS discovery.
const (
	ServiceType   = "_clipdrop._tcp"
	Domain        = "local."
	StatusReady   = "ready"
	StatusPairing = "pairing"
)

// Record represents the decoded attributes of a Clipdrop mDNS TXT record.
type Record struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OS     string `json:"os"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// BuildInstanceName generates a unique instance name adhering to the specification:
// <first-16-fingerprint>-<hostname>.
func BuildInstanceName(deviceID, hostname string) string {
	normID := strings.ToLower(strings.TrimSpace(deviceID))
	if len(normID) > 16 {
		normID = normID[:16]
	}
	normHost := strings.TrimSpace(hostname)
	if normHost == "" {
		normHost = "node"
	}
	return fmt.Sprintf("%s-%s", normID, normHost)
}

// BuildTXT serializes a Record into DNS-SD TXT record key=value pairs.
func BuildTXT(r Record) []string {
	proto := r.Proto
	if proto == "" {
		proto = "1"
	}
	status := r.Status
	if status == "" {
		status = StatusReady
	}

	return []string{
		"id=" + strings.ToLower(strings.TrimSpace(r.ID)),
		"name=" + strings.TrimSpace(r.Name),
		"os=" + strings.TrimSpace(r.OS),
		"proto=" + proto,
		"status=" + status,
	}
}

// ParseTXT deserializes DNS-SD TXT key=value pairs into a Record struct.
func ParseTXT(txt []string) Record {
	var r Record
	for _, item := range txt {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := parts[0], parts[1]
		switch k {
		case "id":
			r.ID = strings.ToLower(strings.TrimSpace(v))
		case "name":
			r.Name = strings.TrimSpace(v)
		case "os":
			r.OS = strings.TrimSpace(v)
		case "proto":
			r.Proto = strings.TrimSpace(v)
		case "status":
			r.Status = strings.TrimSpace(v)
		}
	}
	return r
}
