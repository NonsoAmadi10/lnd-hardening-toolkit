package checks

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/NonsoAmadi10/lnd-hardening-toolkit/pkg/scanner"
)

// sensitiveFile defines a file to check and its expected permissions.
type sensitiveFile struct {
	path     string
	name     string
	maxPerm  fs.FileMode
	severity scanner.Severity
	module   string
}

// CheckFilePermissions audits permissions on sensitive LND files.
// It checks wallet.db, tls.key, macaroons, channel.backup, lnd.conf,
// and the Tor onion private key.
func CheckFilePermissions(paths FilePaths) []scanner.Finding {
	targets := []sensitiveFile{
		{paths.WalletDB, "wallet.db", 0600, scanner.Critical, "keys"},
		{paths.TLSKey, "tls.key", 0600, scanner.Critical, "keys"},
		{paths.AdminMacaroon, "admin.macaroon", 0600, scanner.Critical, "access"},
		{paths.ReadonlyMacaroon, "readonly.macaroon", 0600, scanner.High, "access"},
		{paths.InvoiceMacaroon, "invoice.macaroon", 0600, scanner.High, "access"},
		{paths.ChannelBackup, "channel.backup", 0600, scanner.Critical, "keys"},
		{paths.ConfigFile, "lnd.conf", 0640, scanner.High, "access"},
	}

	// Tor onion key if provided
	if paths.TorOnionKey != "" {
		targets = append(targets, sensitiveFile{
			path:     paths.TorOnionKey,
			name:     "tor onion private key",
			maxPerm:  0600,
			severity: scanner.Critical,
			module:   "keys",
		})
	}

	var findings []scanner.Finding

	for _, t := range targets {
		if t.path == "" {
			continue
		}

		f := checkSingleFile(t)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func checkSingleFile(sf sensitiveFile) *scanner.Finding {
	info, err := os.Stat(sf.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist — not a permission issue
		}
		return &scanner.Finding{
			ID:          fmt.Sprintf("PERM-%s", sf.name),
			Module:      sf.module,
			Severity:    scanner.Low,
			Title:       fmt.Sprintf("Cannot stat %s", sf.name),
			Description: fmt.Sprintf("Unable to check permissions on %s: %v", sf.path, err),
		}
	}

	perm := info.Mode().Perm()

	// Check if actual permissions exceed the maximum allowed
	if isOverlyPermissive(perm, sf.maxPerm) {
		return &scanner.Finding{
			ID:       fmt.Sprintf("PERM-%s", sf.name),
			Module:   sf.module,
			Severity: sf.severity,
			Title:    fmt.Sprintf("%s has permissions %04o (too permissive)", sf.name, perm),
			Description: fmt.Sprintf(
				"%s at %s has permissions %04o. Maximum recommended: %04o.",
				sf.name, sf.path, perm, sf.maxPerm,
			),
			Remediation: fmt.Sprintf("chmod %04o %s", sf.maxPerm, sf.path),
		}
	}

	return nil
}

// isOverlyPermissive returns true if the actual permission grants access
// beyond what maxPerm allows. We check group and other bits.
func isOverlyPermissive(actual, maxPerm fs.FileMode) bool {
	// If the file allows any bits that maxPerm doesn't, it's too permissive.
	// For example, if maxPerm is 0600 and actual is 0644, the group-read (040)
	// and other-read (004) bits exceed the maximum.
	excess := actual & ^maxPerm
	return excess != 0
}

// FilePaths holds the resolved paths to files that need permission checking.
type FilePaths struct {
	WalletDB         string
	TLSKey           string
	AdminMacaroon    string
	ReadonlyMacaroon string
	InvoiceMacaroon  string
	ChannelBackup    string
	ConfigFile       string
	TorOnionKey      string
}
