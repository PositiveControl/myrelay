package security

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Status represents the security hardening status of a VPN node.
type Status struct {
	Timestamp          string          `json:"timestamp"`
	Fail2Ban           Fail2BanStatus  `json:"fail2ban"`
	SSH                SSHStatus       `json:"ssh"`
	UnattendedUpgrades UpgradeStatus   `json:"unattended_upgrades"`
	Firewall           FirewallStatus  `json:"firewall"`
	TLS                TLSStatus       `json:"tls"`
}

// Fail2BanStatus reports fail2ban state.
type Fail2BanStatus struct {
	Installed     bool   `json:"installed"`
	Active        bool   `json:"active"`
	SSHJail       bool   `json:"ssh_jail_enabled"`
	CurrentlyBanned int  `json:"currently_banned"`
	TotalBanned   int    `json:"total_banned"`
	CurrentFailed int    `json:"current_failed"`
	TotalFailed   int    `json:"total_failed"`
}

// SSHStatus reports SSH hardening config.
type SSHStatus struct {
	PermitRootLogin      string `json:"permit_root_login"`
	PasswordAuth         bool   `json:"password_auth"`
	X11Forwarding        bool   `json:"x11_forwarding"`
	MaxAuthTries         int    `json:"max_auth_tries"`
	RootLoginHardened    bool   `json:"root_login_hardened"`
	PasswordAuthDisabled bool   `json:"password_auth_disabled"`
}

// UpgradeStatus reports unattended-upgrades state.
type UpgradeStatus struct {
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	LastRun   string `json:"last_run,omitempty"`
}

// FirewallStatus reports UFW state.
type FirewallStatus struct {
	Active bool     `json:"active"`
	Rules  []string `json:"rules"`
}

// TLSStatus reports TLS configuration.
type TLSStatus struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file,omitempty"`
}

// Collect gathers the current security status from the local system.
func Collect(tlsEnabled bool, tlsCertFile string) Status {
	return Status{
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		Fail2Ban:           collectFail2Ban(),
		SSH:                collectSSH(),
		UnattendedUpgrades: collectUpgrades(),
		Firewall:           collectFirewall(),
		TLS: TLSStatus{
			Enabled:  tlsEnabled,
			CertFile: tlsCertFile,
		},
	}
}

func collectFail2Ban() Fail2BanStatus {
	s := Fail2BanStatus{}

	// Check installed
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return s
	}
	s.Installed = true

	// Check active
	out, err := exec.Command("systemctl", "is-active", "fail2ban").Output()
	s.Active = err == nil && strings.TrimSpace(string(out)) == "active"

	if !s.Active {
		return s
	}

	// Get SSH jail status
	jailOut, err := exec.Command("fail2ban-client", "status", "sshd").Output()
	if err != nil {
		return s
	}
	s.SSHJail = true

	for _, line := range strings.Split(string(jailOut), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Currently banned:") {
			s.CurrentlyBanned = parseTrailingInt(line)
		} else if strings.Contains(line, "Total banned:") {
			s.TotalBanned = parseTrailingInt(line)
		} else if strings.Contains(line, "Currently failed:") {
			s.CurrentFailed = parseTrailingInt(line)
		} else if strings.Contains(line, "Total failed:") {
			s.TotalFailed = parseTrailingInt(line)
		}
	}

	return s
}

func collectSSH() SSHStatus {
	s := SSHStatus{
		PermitRootLogin: "unknown",
		MaxAuthTries:    6, // default
	}

	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		return s
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.ToLower(parts[0]), parts[1]
		switch key {
		case "permitrootlogin":
			s.PermitRootLogin = val
			s.RootLoginHardened = val == "prohibit-password" || val == "without-password" || val == "no" || val == "forced-commands-only"
		case "passwordauthentication":
			s.PasswordAuth = val == "yes"
			s.PasswordAuthDisabled = val == "no"
		case "x11forwarding":
			s.X11Forwarding = val == "yes"
		case "maxauthtries":
			if n, err := strconv.Atoi(val); err == nil {
				s.MaxAuthTries = n
			}
		}
	}

	return s
}

func collectUpgrades() UpgradeStatus {
	s := UpgradeStatus{}

	// Check installed
	out, err := exec.Command("dpkg", "-s", "unattended-upgrades").Output()
	s.Installed = err == nil && strings.Contains(string(out), "Status: install ok installed")

	if !s.Installed {
		return s
	}

	// Check active
	activeOut, err := exec.Command("systemctl", "is-active", "unattended-upgrades").Output()
	s.Active = err == nil && strings.TrimSpace(string(activeOut)) == "active"

	// Check last run
	stampOut, err := exec.Command("stat", "-c", "%Y", "/var/lib/apt/periodic/unattended-upgrades-stamp").Output()
	if err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(string(stampOut)), 10, 64); err == nil {
			s.LastRun = time.Unix(ts, 0).UTC().Format(time.RFC3339)
		}
	}

	return s
}

func collectFirewall() FirewallStatus {
	s := FirewallStatus{}

	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return s
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			s.Active = strings.Contains(line, "active")
		} else if len(line) > 0 && !strings.HasPrefix(line, "--") && !strings.HasPrefix(line, "To") && !strings.HasPrefix(line, "Status") {
			s.Rules = append(s.Rules, line)
		}
	}
	if s.Rules == nil {
		s.Rules = []string{}
	}

	return s
}

func parseTrailingInt(line string) int {
	parts := strings.Split(line, "\t")
	if len(parts) < 2 {
		parts = strings.Fields(line)
	}
	if len(parts) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(parts[len(parts)-1]))
	return n
}
