package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/PositiveControl/myrelay/pkg/tlsutil"
	"github.com/rivo/tview"
)

// Color constants for consistent theming.
var (
	colorCyan      = tcell.NewRGBColor(0, 255, 255)
	colorLightCyan = tcell.NewRGBColor(224, 255, 255)
	colorLightGray = tcell.NewRGBColor(211, 211, 211)
)

// ---------------------------------------------------------------------------
// Data models
// ---------------------------------------------------------------------------

type HealthResp struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	IP           string `json:"ip"`
	Region       string `json:"region"`
	PublicKey    string `json:"public_key"`
	Endpoint     string `json:"endpoint"`
	OwnerID  string `json:"owner_id"`
	MaxPeers int    `json:"max_peers"`
	Status       string `json:"status"`
}

type User struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	PublicKey      string `json:"public_key"`
	PrivateKey     string `json:"-"`
	Address        string `json:"address"`
	AssignedNodeID string `json:"assigned_node_id"`
	Plan           string `json:"plan"`
	BandwidthUsed  int64  `json:"bandwidth_used"`
	BandwidthLimit int64  `json:"bandwidth_limit"`
	CreatedAt      string `json:"created_at"`
}

type SecurityStatus struct {
	Timestamp          string            `json:"timestamp"`
	Fail2Ban           Fail2BanStatus    `json:"fail2ban"`
	SSH                SSHSecStatus      `json:"ssh"`
	UnattendedUpgrades UpgradeStatus     `json:"unattended_upgrades"`
	Firewall           FirewallStatus    `json:"firewall"`
	TLS                TLSSecStatus      `json:"tls"`
}

type Fail2BanStatus struct {
	Installed       bool `json:"installed"`
	Active          bool `json:"active"`
	SSHJail         bool `json:"ssh_jail_enabled"`
	CurrentlyBanned int  `json:"currently_banned"`
	TotalBanned     int  `json:"total_banned"`
	CurrentFailed   int  `json:"current_failed"`
	TotalFailed     int  `json:"total_failed"`
}

type SSHSecStatus struct {
	PermitRootLogin      string `json:"permit_root_login"`
	PasswordAuth         bool   `json:"password_auth"`
	X11Forwarding        bool   `json:"x11_forwarding"`
	MaxAuthTries         int    `json:"max_auth_tries"`
	RootLoginHardened    bool   `json:"root_login_hardened"`
	PasswordAuthDisabled bool   `json:"password_auth_disabled"`
}

type UpgradeStatus struct {
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	LastRun   string `json:"last_run,omitempty"`
}

type FirewallStatus struct {
	Active bool     `json:"active"`
	Rules  []string `json:"rules"`
}

type TLSSecStatus struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file,omitempty"`
}

type BandwidthEntry struct {
	PublicKey        string `json:"public_key"`
	TotalReceived    int64  `json:"total_received"`
	TotalSent        int64  `json:"total_sent"`
	IntervalReceived int64  `json:"interval_received"`
	IntervalSent     int64  `json:"interval_sent"`
	LastUpdated      string `json:"last_updated"`
}

// ---------------------------------------------------------------------------
// Snapshot — immutable data passed from poller to UI via channel
// ---------------------------------------------------------------------------

type Snapshot struct {
	Healthy        bool
	Nodes          []Node
	Users          []User
	NodeBandwidth  map[string][]BandwidthEntry
	NodeSecurity   map[string]*SecurityStatus
	TotalBWIn      int64
	TotalBWOut     int64
	FetchedAt      time.Time
}

// ---------------------------------------------------------------------------
// UI-only state (only touched on the main/UI goroutine — no locks needed)
// ---------------------------------------------------------------------------

type UIState struct {
	activeTab       int
	nodeSortCol     int
	nodeSortReverse bool
	userSortCol     int
	userSortReverse bool
	userFilter      string
	filterMode      bool
	showHelp        bool
	showNodeDetail  bool
	showUserDetail  bool
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

type APIClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewAPIClient() *APIClient {
	base := os.Getenv("VPN_API_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	base = strings.TrimRight(base, "/")

	client := &http.Client{Timeout: 5 * time.Second}

	// Load internal CA certificate for TLS verification if configured.
	if caPath := os.Getenv("TLS_CA_CERT"); caPath != "" {
		tlsCfg, err := tlsutil.ClientTLSConfig(caPath)
		if err != nil {
			log.Printf("warning: failed to load CA cert %s: %v (falling back to system roots)", caPath, err)
		} else {
			client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}
	} else if strings.HasPrefix(base, "https://") {
		// HTTPS URL but no CA cert — skip verification for self-signed certs.
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &APIClient{
		baseURL: base,
		token:   os.Getenv("VPN_ADMIN_TOKEN"),
		client:  client,
	}
}

func (c *APIClient) get(path string, out interface{}) error {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

func (c *APIClient) CheckHealth() (*HealthResp, error) {
	var h HealthResp
	err := c.get("/api/health", &h)
	return &h, err
}

func (c *APIClient) GetNodes() ([]Node, error) {
	var nodes []Node
	err := c.get("/api/nodes", &nodes)
	return nodes, err
}

func (c *APIClient) GetUsers() ([]User, error) {
	var users []User
	err := c.get("/api/users", &users)
	return users, err
}

func (c *APIClient) GetNodeBandwidth(nodeID string) ([]BandwidthEntry, error) {
	var entries []BandwidthEntry
	err := c.get(fmt.Sprintf("/api/nodes/%s/bandwidth", nodeID), &entries)
	return entries, err
}

func (c *APIClient) GetNodeSecurity(nodeID string) (*SecurityStatus, error) {
	var status SecurityStatus
	err := c.get(fmt.Sprintf("/api/nodes/%s/security", nodeID), &status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// fetchSnapshot does all API calls and returns an immutable Snapshot.
// Runs on the poller goroutine — never touches UI.
func (c *APIClient) fetchSnapshot() Snapshot {
	snap := Snapshot{
		NodeBandwidth: make(map[string][]BandwidthEntry),
		NodeSecurity:  make(map[string]*SecurityStatus),
		FetchedAt:     time.Now(),
	}

	_, err := c.CheckHealth()
	snap.Healthy = err == nil

	nodes, err := c.GetNodes()
	if err == nil {
		snap.Nodes = nodes
		for _, node := range nodes {
			entries, err := c.GetNodeBandwidth(node.ID)
			if err == nil {
				snap.NodeBandwidth[node.ID] = entries
				for _, e := range entries {
					snap.TotalBWIn += e.TotalReceived
					snap.TotalBWOut += e.TotalSent
				}
			}
			sec, err := c.GetNodeSecurity(node.ID)
			if err == nil {
				snap.NodeSecurity[node.ID] = sec
			}
		}
	}

	users, err := c.GetUsers()
	if err == nil {
		snap.Users = users
	}

	return snap
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}



func bandwidthBar(used, limit int64, width int) string {
	if limit <= 0 {
		return strings.Repeat("░", width)
	}
	pct := float64(used) / float64(limit)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func bandwidthColor(used, limit int64) string {
	if limit <= 0 {
		return "gray"
	}
	pct := float64(used) / float64(limit)
	switch {
	case pct >= 0.9:
		return "red"
	case pct >= 0.7:
		return "yellow"
	default:
		return "green"
	}
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "active", "online", "healthy":
		return "green"
	case "warning", "degraded":
		return "yellow"
	default:
		return "red"
	}
}

var regionNames = map[string]string{
	"hil":     "Oregon, US",
	"ash":     "Virginia, US",
	"nbg1":    "Nuremberg, DE",
	"fsn1":    "Falkenstein, DE",
	"hel1":    "Helsinki, FI",
	"sin":     "Singapore, SG",
	"us-west": "Oregon, US",
	"us-east": "Virginia, US",
	"eu-fin":  "Helsinki, FI",
	"eu-de":   "Germany, DE",
	"ap-sgp":  "Singapore, SG",
}

func friendlyRegion(region string) string {
	if name, ok := regionNames[region]; ok {
		return name
	}
	return region
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// ---------------------------------------------------------------------------
// TUI application
// ---------------------------------------------------------------------------

type TUI struct {
	app   *tview.Application
	pages *tview.Pages
	ui    UIState
	snap  Snapshot // current snapshot, only read/written on UI goroutine
	api   *APIClient

	// Main layout
	mainFlex    *tview.Flex
	header      *tview.TextView
	footer      *tview.TextView
	tabBar      *tview.TextView
	contentArea *tview.Flex

	// Tab content
	dashboardPage *tview.Flex
	nodesPage     *tview.Flex
	usersPage     *tview.Flex
	securityPage  *tview.Flex

	// Security widgets
	securityView *tview.TextView

	// Dashboard widgets
	statBoxes *tview.Flex
	nodeCards *tview.Flex

	// Tables
	nodeTable *tview.Table
	userTable *tview.Table
	filterBox *tview.InputField

	// Root pages for modals
	rootPages *tview.Pages
}

func NewTUI() *TUI {
	t := &TUI{
		app: tview.NewApplication(),
		snap: Snapshot{
			NodeBandwidth: make(map[string][]BandwidthEntry),
			NodeSecurity:  make(map[string]*SecurityStatus),
		},
		api: NewAPIClient(),
	}
	t.buildUI()
	return t
}

func (t *TUI) buildUI() {
	// Header
	t.header = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	t.header.SetBackgroundColor(tcell.ColorDarkBlue)

	// Tab bar
	t.tabBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	t.tabBar.SetBackgroundColor(tcell.NewRGBColor(30, 30, 50))

	// Footer
	t.footer = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	t.footer.SetBackgroundColor(tcell.NewRGBColor(30, 30, 50))

	// Build tab content
	t.buildDashboardPage()
	t.buildNodesPage()
	t.buildUsersPage()
	t.buildSecurityPage()

	// Content area with pages
	t.contentArea = tview.NewFlex()
	t.pages = tview.NewPages().
		AddPage("dashboard", t.dashboardPage, true, true).
		AddPage("nodes", t.nodesPage, true, false).
		AddPage("users", t.usersPage, true, false).
		AddPage("security", t.securityPage, true, false)

	// Main layout
	t.mainFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.header, 1, 0, false).
		AddItem(t.tabBar, 1, 0, false).
		AddItem(t.pages, 0, 1, true).
		AddItem(t.footer, 1, 0, false)

	// Root pages: main + overlays
	t.rootPages = tview.NewPages().
		AddPage("main", t.mainFlex, true, true)

	t.app.SetRoot(t.rootPages, true)

	// Global input capture
	t.app.SetInputCapture(t.handleInput)
}

func (t *TUI) handleInput(event *tcell.EventKey) *tcell.EventKey {
	// Help overlay dismissal
	if t.ui.showHelp {
		t.ui.showHelp = false
		t.rootPages.RemovePage("help")
		return nil
	}

	// Modal dismissal
	if t.ui.showNodeDetail {
		if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyEnter {
			t.ui.showNodeDetail = false
			t.rootPages.RemovePage("nodeDetail")
			return nil
		}
		return event
	}
	if t.ui.showUserDetail {
		if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyEnter {
			t.ui.showUserDetail = false
			t.rootPages.RemovePage("userDetail")
			return nil
		}
		return event
	}

	// Filter mode
	if t.ui.filterMode {
		if event.Key() == tcell.KeyEscape {
			t.ui.filterMode = false
			t.ui.userFilter = ""
			t.filterBox.SetText("")
			t.app.SetFocus(t.userTable)
			t.refreshUsersTable()
			return nil
		}
		if event.Key() == tcell.KeyEnter {
			t.ui.filterMode = false
			t.ui.userFilter = t.filterBox.GetText()
			t.app.SetFocus(t.userTable)
			t.refreshUsersTable()
			return nil
		}
		return event
	}

	switch event.Key() {
	case tcell.KeyCtrlC:
		t.app.Stop()
		return nil
	case tcell.KeyTab:
		t.ui.activeTab = (t.ui.activeTab + 1) % 4
		t.switchTab()
		return nil
	case tcell.KeyEscape:
		if t.ui.activeTab == 2 && t.ui.userFilter != "" {
			t.ui.userFilter = ""
			t.filterBox.SetText("")
			t.refreshUsersTable()
			return nil
		}
		return event
	case tcell.KeyEnter:
		if t.ui.activeTab == 1 && len(t.snap.Nodes) > 0 {
			t.showNodeDetailModal()
			return nil
		}
		if t.ui.activeTab == 2 && len(t.snap.Users) > 0 {
			t.showUserDetailModal()
			return nil
		}
	}

	switch event.Rune() {
	case 'q':
		t.app.Stop()
		return nil
	case '1':
		t.ui.activeTab = 0
		t.switchTab()
		return nil
	case '2':
		t.ui.activeTab = 1
		t.switchTab()
		return nil
	case '3':
		t.ui.activeTab = 2
		t.switchTab()
		return nil
	case '4':
		t.ui.activeTab = 3
		t.switchTab()
		return nil
	case 's':
		if t.ui.activeTab == 1 {
			t.ui.nodeSortCol = (t.ui.nodeSortCol + 1) % 8
			t.refreshNodesTable()
		} else if t.ui.activeTab == 2 {
			t.ui.userSortCol = (t.ui.userSortCol + 1) % 7
			t.refreshUsersTable()
		}
		return nil
	case 'r':
		if t.ui.activeTab == 1 {
			t.ui.nodeSortReverse = !t.ui.nodeSortReverse
			t.refreshNodesTable()
		} else if t.ui.activeTab == 2 {
			t.ui.userSortReverse = !t.ui.userSortReverse
			t.refreshUsersTable()
		}
		return nil
	case '/':
		if t.ui.activeTab == 2 {
			t.ui.filterMode = true
			t.filterBox.SetText(t.ui.userFilter)
			t.app.SetFocus(t.filterBox)
			return nil
		}
	case '?':
		t.showHelpOverlay()
		return nil
	}

	return event
}

func (t *TUI) buildDashboardPage() {
	t.statBoxes = tview.NewFlex().SetDirection(tview.FlexColumn)
	t.nodeCards = tview.NewFlex().SetDirection(tview.FlexRow)

	cardScroll := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.nodeCards, 0, 1, false)

	t.dashboardPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.statBoxes, 5, 0, false).
		AddItem(cardScroll, 0, 1, false)
}

func (t *TUI) buildNodesPage() {
	t.nodeTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(tview.Borders.Vertical)
	t.nodeTable.SetBackgroundColor(tcell.ColorDefault)
	t.nodeTable.SetSelectedStyle(tcell.StyleDefault.
		Foreground(tcell.ColorWhite).
		Background(tcell.NewRGBColor(40, 60, 100)))

	t.nodesPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.nodeTable, 0, 1, true)
}

func (t *TUI) buildUsersPage() {
	t.userTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(tview.Borders.Vertical)
	t.userTable.SetBackgroundColor(tcell.ColorDefault)
	t.userTable.SetSelectedStyle(tcell.StyleDefault.
		Foreground(tcell.ColorWhite).
		Background(tcell.NewRGBColor(40, 60, 100)))

	t.filterBox = tview.NewInputField().
		SetLabel(" Filter: ").
		SetFieldWidth(40).
		SetFieldBackgroundColor(tcell.NewRGBColor(40, 40, 60)).
		SetLabelColor(colorCyan)

	filterRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(t.filterBox, 0, 1, false)
	filterRow.SetBackgroundColor(tcell.NewRGBColor(30, 30, 50))

	t.usersPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(filterRow, 1, 0, false).
		AddItem(t.userTable, 0, 1, true)
}

func (t *TUI) buildSecurityPage() {
	t.securityView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	t.securityView.SetBackgroundColor(tcell.NewRGBColor(15, 15, 25))
	t.securityView.SetBorder(true).
		SetTitle(" Security Hardening Status ").
		SetTitleColor(colorCyan).
		SetBorderColor(tcell.NewRGBColor(60, 60, 100))

	t.securityPage = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.securityView, 0, 1, true)
}

func (t *TUI) refreshSecurityView() {
	var sb strings.Builder

	if len(t.snap.Nodes) == 0 {
		sb.WriteString("\n [gray]No nodes available[-]")
		t.securityView.SetText(sb.String())
		return
	}

	for _, node := range t.snap.Nodes {
		sec := t.snap.NodeSecurity[node.ID]

		location := friendlyRegion(node.Region)
		sb.WriteString(fmt.Sprintf("\n [bold][cyan]%s[-] [white]— %s[-] [gray](%s)[-]\n", node.Name, location, node.IP))
		sb.WriteString(fmt.Sprintf(" %s\n", strings.Repeat("─", 70)))

		if sec == nil {
			sb.WriteString(" [red]Unable to retrieve security status[-]\n\n")
			continue
		}

		// TLS
		if sec.TLS.Enabled {
			sb.WriteString(" [green]✓[-] [bold]TLS[-]                    [green]Enabled[-]\n")
		} else {
			sb.WriteString(" [red]✗[-] [bold]TLS[-]                    [red]Disabled[-] — traffic unencrypted\n")
		}

		// Fail2Ban
		if sec.Fail2Ban.Active {
			sb.WriteString(fmt.Sprintf(" [green]✓[-] [bold]Fail2Ban[-]               [green]Active[-]"))
			if sec.Fail2Ban.SSHJail {
				sb.WriteString(fmt.Sprintf("  SSH jail: [white]%d[-] banned, [white]%d[-] failed",
					sec.Fail2Ban.CurrentlyBanned, sec.Fail2Ban.CurrentFailed))
			}
			sb.WriteString("\n")
			sb.WriteString(fmt.Sprintf("                              Total banned: [yellow]%d[-]  Total failed: [yellow]%d[-]\n",
				sec.Fail2Ban.TotalBanned, sec.Fail2Ban.TotalFailed))
		} else if sec.Fail2Ban.Installed {
			sb.WriteString(" [yellow]![-] [bold]Fail2Ban[-]               [yellow]Installed but inactive[-]\n")
		} else {
			sb.WriteString(" [red]✗[-] [bold]Fail2Ban[-]               [red]Not installed[-]\n")
		}

		// SSH
		sb.WriteString(" ")
		if sec.SSH.RootLoginHardened {
			sb.WriteString("[green]✓[-]")
		} else {
			sb.WriteString("[red]✗[-]")
		}
		sb.WriteString(fmt.Sprintf(" [bold]SSH Root Login[-]         [white]%s[-]", sec.SSH.PermitRootLogin))
		if sec.SSH.RootLoginHardened {
			sb.WriteString(" [green](hardened)[-]")
		} else {
			sb.WriteString(" [red](vulnerable)[-]")
		}
		sb.WriteString("\n")

		sb.WriteString(" ")
		if sec.SSH.PasswordAuthDisabled {
			sb.WriteString("[green]✓[-]")
		} else {
			sb.WriteString("[red]✗[-]")
		}
		sb.WriteString(" [bold]SSH Password Auth[-]      ")
		if sec.SSH.PasswordAuthDisabled {
			sb.WriteString("[green]Disabled[-]\n")
		} else {
			sb.WriteString("[red]Enabled[-] — brute force risk\n")
		}

		sb.WriteString(" ")
		if !sec.SSH.X11Forwarding {
			sb.WriteString("[green]✓[-]")
		} else {
			sb.WriteString("[yellow]![-]")
		}
		sb.WriteString(" [bold]X11 Forwarding[-]        ")
		if sec.SSH.X11Forwarding {
			sb.WriteString("[yellow]Enabled[-]\n")
		} else {
			sb.WriteString("[green]Disabled[-]\n")
		}

		sb.WriteString(fmt.Sprintf(" [white]·[-] [bold]Max Auth Tries[-]        [white]%d[-]", sec.SSH.MaxAuthTries))
		if sec.SSH.MaxAuthTries <= 3 {
			sb.WriteString(" [green](good)[-]")
		} else if sec.SSH.MaxAuthTries <= 6 {
			sb.WriteString(" [yellow](default)[-]")
		} else {
			sb.WriteString(" [red](too high)[-]")
		}
		sb.WriteString("\n")

		// Unattended Upgrades
		if sec.UnattendedUpgrades.Active {
			lastRun := sec.UnattendedUpgrades.LastRun
			if lastRun == "" {
				lastRun = "never"
			}
			sb.WriteString(fmt.Sprintf(" [green]✓[-] [bold]Auto Security Updates[-]  [green]Active[-]  Last run: [white]%s[-]\n", lastRun))
		} else if sec.UnattendedUpgrades.Installed {
			sb.WriteString(" [yellow]![-] [bold]Auto Security Updates[-]  [yellow]Installed but inactive[-]\n")
		} else {
			sb.WriteString(" [red]✗[-] [bold]Auto Security Updates[-]  [red]Not installed[-]\n")
		}

		// Firewall
		if sec.Firewall.Active {
			sb.WriteString(fmt.Sprintf(" [green]✓[-] [bold]Firewall (UFW)[-]        [green]Active[-]  [white]%d rules[-]\n", len(sec.Firewall.Rules)))
		} else {
			sb.WriteString(" [red]✗[-] [bold]Firewall (UFW)[-]        [red]Inactive[-]\n")
		}

		// Score
		score := 0
		total := 6
		if sec.TLS.Enabled {
			score++
		}
		if sec.Fail2Ban.Active && sec.Fail2Ban.SSHJail {
			score++
		}
		if sec.SSH.RootLoginHardened {
			score++
		}
		if sec.SSH.PasswordAuthDisabled {
			score++
		}
		if sec.UnattendedUpgrades.Active {
			score++
		}
		if sec.Firewall.Active {
			score++
		}

		scoreColor := "red"
		if score == total {
			scoreColor = "green"
		} else if score >= total-1 {
			scoreColor = "yellow"
		}
		sb.WriteString(fmt.Sprintf("\n [bold]Security Score: [%s]%d/%d[-][-]\n\n", scoreColor, score, total))
	}

	t.securityView.SetText(sb.String())
}

func (t *TUI) switchTab() {
	switch t.ui.activeTab {
	case 0:
		t.refreshDashboard()
		t.pages.SwitchToPage("dashboard")
	case 1:
		t.refreshNodesTable()
		t.pages.SwitchToPage("nodes")
		t.app.SetFocus(t.nodeTable)
	case 2:
		t.refreshUsersTable()
		t.pages.SwitchToPage("users")
		t.app.SetFocus(t.userTable)
	case 3:
		t.refreshSecurityView()
		t.pages.SwitchToPage("security")
	}
	t.updateTabBar()
	t.updateFooter()
}

// ---------------------------------------------------------------------------
// Header / Footer / Tab bar
// ---------------------------------------------------------------------------

func (t *TUI) updateHeader() {
	statusDot := "[red]● DISCONNECTED[-]"
	if t.snap.Healthy {
		statusDot = "[green]● CONNECTED[-]"
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	refreshAgo := ""
	if !t.snap.FetchedAt.IsZero() {
		refreshAgo = fmt.Sprintf(" [gray](refreshed %s ago)[-]", time.Since(t.snap.FetchedAt).Truncate(time.Second))
	}

	t.header.SetText(fmt.Sprintf(
		" [bold][cyan]VPN Control Plane[-][white]  %s  [gray]│[-]  [white]%s[-]%s",
		statusDot, now, refreshAgo,
	))
}

func (t *TUI) updateTabBar() {
	tabs := []string{"Dashboard", "Nodes", "Users", "Security"}
	var parts []string
	for i, name := range tabs {
		if i == t.ui.activeTab {
			parts = append(parts, fmt.Sprintf(" [#000000:#00ffaf:b] %d %s [-:-:-] ", i+1, name))
		} else {
			parts = append(parts, fmt.Sprintf(" [#aaaaaa]%d %s[-] ", i+1, name))
		}
	}
	t.tabBar.SetText(strings.Join(parts, " "))
}

func (t *TUI) updateFooter() {
	var hint string
	switch t.ui.activeTab {
	case 0:
		hint = "[cyan]1-4[-] tabs  [cyan]?[-] help  [cyan]q[-] quit"
	case 1:
		hint = "[cyan]↑↓[-] navigate  [cyan]Enter[-] detail  [cyan]s[-] sort  [cyan]r[-] reverse  [cyan]1-4[-] tabs  [cyan]?[-] help  [cyan]q[-] quit"
	case 2:
		filter := ""
		if t.ui.userFilter != "" {
			filter = fmt.Sprintf("  [yellow]filter: %s[-]", t.ui.userFilter)
		}
		hint = fmt.Sprintf("[cyan]↑↓[-] navigate  [cyan]Enter[-] detail  [cyan]/[-] filter  [cyan]Esc[-] clear  [cyan]s[-] sort  [cyan]r[-] reverse  [cyan]q[-] quit%s", filter)
	case 3:
		hint = "[cyan]1-4[-] tabs  [cyan]?[-] help  [cyan]q[-] quit"
	}
	t.footer.SetText(hint)
}

// ---------------------------------------------------------------------------
// Dashboard rendering
// ---------------------------------------------------------------------------

func makeStatBox(title, value string, color tcell.Color) *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	tv.SetBorder(true).
		SetBorderColor(color).
		SetTitle(fmt.Sprintf(" %s ", title)).
		SetTitleColor(color).
		SetTitleAlign(tview.AlignCenter)
	tv.SetBackgroundColor(tcell.NewRGBColor(20, 20, 35))
	tv.SetText(fmt.Sprintf("\n[bold]%s[-]", value))
	return tv
}

func (t *TUI) refreshDashboard() {
	nodes := t.snap.Nodes
	users := t.snap.Users

	dedicatedNodes := 0
	activeNodes := 0
	for _, n := range nodes {
		if n.OwnerID != "" {
			dedicatedNodes++
		}
		if strings.EqualFold(n.Status, "active") || strings.EqualFold(n.Status, "online") {
			activeNodes++
		}
	}

	// Stat boxes
	t.statBoxes.Clear()
	t.statBoxes.AddItem(makeStatBox("NODES", fmt.Sprintf("%d / %d active", activeNodes, len(nodes)), colorCyan), 0, 1, false)
	t.statBoxes.AddItem(makeStatBox("USERS", fmt.Sprintf("%d", len(users)), tcell.ColorBlue), 0, 1, false)
	t.statBoxes.AddItem(makeStatBox("DEDICATED", fmt.Sprintf("%d / %d", dedicatedNodes, len(nodes)), tcell.ColorGreen), 0, 1, false)
	t.statBoxes.AddItem(makeStatBox("BANDWIDTH", fmt.Sprintf("↓%s  ↑%s", formatBytes(t.snap.TotalBWIn), formatBytes(t.snap.TotalBWOut)), tcell.ColorYellow), 0, 1, false)

	// Node cards
	t.nodeCards.Clear()

	if len(nodes) == 0 {
		empty := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
		empty.SetText("\n[gray]No nodes available[-]")
		t.nodeCards.AddItem(empty, 3, 0, false)
		return
	}

	// Lay out node cards in rows of 3
	row := tview.NewFlex().SetDirection(tview.FlexColumn)
	for i, node := range nodes {
		card := t.makeNodeCard(node, t.snap.NodeBandwidth[node.ID])
		row.AddItem(card, 0, 1, false)
		if (i+1)%3 == 0 || i == len(nodes)-1 {
			t.nodeCards.AddItem(row, 8, 0, false)
			if i < len(nodes)-1 {
				row = tview.NewFlex().SetDirection(tview.FlexColumn)
			}
		}
	}
}

func (t *TUI) makeNodeCard(node Node, bwEntries []BandwidthEntry) *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true).
		SetBorderColor(tcell.NewRGBColor(80, 140, 200)).
		SetBackgroundColor(tcell.NewRGBColor(15, 15, 25))

	sColor := statusColor(node.Status)
	ownerStr := "[gray]unassigned[-]"
	if node.OwnerID != "" {
		ownerStr = fmt.Sprintf("[white::b]%s[-]", truncate(node.OwnerID, 12))
	}

	var bwIn, bwOut int64
	for _, e := range bwEntries {
		bwIn += e.TotalReceived
		bwOut += e.TotalSent
	}

	location := friendlyRegion(node.Region)
	tv.SetTitle(fmt.Sprintf(" [bold]%s[-] [white]— %s[-] ", node.Name, location)).
		SetTitleColor(tcell.NewRGBColor(100, 200, 255)).
		SetTitleAlign(tview.AlignLeft)

	// Bright status colors
	statusStr := strings.ToUpper(node.Status)
	var statusFormatted string
	switch sColor {
	case "green":
		statusFormatted = fmt.Sprintf("[#00ff87::b]● %s[-]", statusStr)
	case "yellow":
		statusFormatted = fmt.Sprintf("[#ffff00::b]● %s[-]", statusStr)
	default:
		statusFormatted = fmt.Sprintf("[#ff5f5f::b]● %s[-]", statusStr)
	}

	peerCount := len(bwEntries)
	peersStr := fmt.Sprintf("[white::b]%d[-]", peerCount)
	if node.MaxPeers > 0 {
		peersStr = fmt.Sprintf("[white::b]%d / %d[-]", peerCount, node.MaxPeers)
	}

	text := fmt.Sprintf(
		" [#5fafff]IP:[-]     [white::b]%s[-]\n"+
			" [#5fafff]Region:[-] [white::b]%s[-]\n"+
			" [#5fafff]Status:[-] %s\n"+
			" [#5fafff]Owner:[-]  %s\n"+
			" [#5fafff]Peers:[-]  %s\n"+
			" [#5fafff]BW:[-]    [white::b]↓%s  ↑%s[-]",
		node.IP, node.Region,
		statusFormatted,
		ownerStr,
		peersStr,
		formatBytes(bwIn), formatBytes(bwOut),
	)
	tv.SetText(text)
	return tv
}

// ---------------------------------------------------------------------------
// Nodes table
// ---------------------------------------------------------------------------

var nodeColumns = []string{"Name", "IP", "Region", "Owner", "Peers", "Status", "BW In", "BW Out"}

func (t *TUI) refreshNodesTable() {
	nodes := make([]Node, len(t.snap.Nodes))
	copy(nodes, t.snap.Nodes)

	// Compute bandwidth per node
	type nodeBW struct{ In, Out int64 }
	nbw := make(map[string]nodeBW)
	for id, entries := range t.snap.NodeBandwidth {
		var in, out int64
		for _, e := range entries {
			in += e.TotalReceived
			out += e.TotalSent
		}
		nbw[id] = nodeBW{in, out}
	}

	// Sort
	col := t.ui.nodeSortCol
	rev := t.ui.nodeSortReverse
	sort.Slice(nodes, func(i, j int) bool {
		var less bool
		a, b := nodes[i], nodes[j]
		switch col {
		case 0:
			less = strings.ToLower(a.Name) < strings.ToLower(b.Name)
		case 1:
			less = a.IP < b.IP
		case 2:
			less = strings.ToLower(a.Region) < strings.ToLower(b.Region)
		case 3:
			less = a.OwnerID < b.OwnerID
		case 4:
			less = len(t.snap.NodeBandwidth[a.ID]) < len(t.snap.NodeBandwidth[b.ID])
		case 5:
			less = a.Status < b.Status
		case 6:
			less = nbw[a.ID].In < nbw[b.ID].In
		case 7:
			less = nbw[a.ID].Out < nbw[b.ID].Out
		default:
			less = a.Name < b.Name
		}
		if rev {
			return !less
		}
		return less
	})

	// Preserve selection
	selRow, selCol := t.nodeTable.GetSelection()
	t.nodeTable.Clear()

	// Header row
	for c, name := range nodeColumns {
		label := name
		if c == col {
			arrow := "▲"
			if rev {
				arrow = "▼"
			}
			label = fmt.Sprintf("%s %s", name, arrow)
		}
		cell := tview.NewTableCell(label).
			SetTextColor(colorCyan).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false).
			SetExpansion(1).
			SetAlign(tview.AlignLeft)
		cell.SetBackgroundColor(tcell.NewRGBColor(30, 30, 60))
		t.nodeTable.SetCell(0, c, cell)
	}

	// Data rows
	for r, node := range nodes {
		row := r + 1
		sColor := statusColor(node.Status)
		nb := nbw[node.ID]

		bgColor := tcell.NewRGBColor(20, 20, 35)
		if row%2 == 0 {
			bgColor = tcell.NewRGBColor(28, 28, 45)
		}

		setCell := func(c int, text string, color tcell.Color) {
			cell := tview.NewTableCell(text).
				SetTextColor(color).
				SetExpansion(1).
				SetAlign(tview.AlignLeft).
				SetBackgroundColor(bgColor)
			t.nodeTable.SetCell(row, c, cell)
		}

		setCell(0, node.Name, tcell.ColorWhite)
		setCell(1, node.IP, colorLightGray)
		setCell(2, node.Region, colorLightGray)

		ownerDisplay := "-"
		ownerColor := colorLightGray
		if node.OwnerID != "" {
			ownerDisplay = truncate(node.OwnerID, 12)
			ownerColor = tcell.ColorWhite
		}
		setCell(3, ownerDisplay, ownerColor)

		peerCount := len(t.snap.NodeBandwidth[node.ID])
		peerStr := fmt.Sprintf("%d", peerCount)
		if node.MaxPeers > 0 {
			peerStr = fmt.Sprintf("%d/%d", peerCount, node.MaxPeers)
		}
		setCell(4, peerStr, tcell.ColorWhite)

		sTColor := tcell.ColorGreen
		switch sColor {
		case "yellow":
			sTColor = tcell.ColorYellow
		case "red":
			sTColor = tcell.ColorRed
		}
		setCell(5, strings.ToUpper(node.Status), sTColor)
		setCell(6, formatBytes(nb.In), colorLightCyan)
		setCell(7, formatBytes(nb.Out), colorLightCyan)
	}

	// Restore selection — disable selectable if no data rows to prevent crashes
	maxRow := t.nodeTable.GetRowCount() - 1
	if maxRow < 1 {
		t.nodeTable.SetSelectable(false, false)
	} else {
		t.nodeTable.SetSelectable(true, false)
		if selRow > maxRow {
			selRow = maxRow
		}
		if selRow < 1 {
			selRow = 1
		}
		t.nodeTable.Select(selRow, selCol)
	}
}

// ---------------------------------------------------------------------------
// Users table
// ---------------------------------------------------------------------------

var userColumns = []string{"Email", "Node", "Plan", "BW Used", "BW Limit", "Address", "Created"}

func (t *TUI) filteredUsers() []User {
	nodeNames := make(map[string]string)
	for _, n := range t.snap.Nodes {
		nodeNames[n.ID] = n.Name
	}

	filter := strings.ToLower(t.ui.userFilter)
	if filter == "" {
		users := make([]User, len(t.snap.Users))
		copy(users, t.snap.Users)
		return users
	}

	users := make([]User, 0, len(t.snap.Users))
	for _, u := range t.snap.Users {
		nn := nodeNames[u.AssignedNodeID]
		match := strings.Contains(strings.ToLower(u.Email), filter) ||
			strings.Contains(strings.ToLower(nn), filter) ||
			strings.Contains(strings.ToLower(u.Plan), filter)
		if match {
			users = append(users, u)
		}
	}
	return users
}

func (t *TUI) refreshUsersTable() {
	users := t.filteredUsers()

	nodeNames := make(map[string]string)
	for _, n := range t.snap.Nodes {
		nodeNames[n.ID] = n.Name
	}

	// Sort
	col := t.ui.userSortCol
	rev := t.ui.userSortReverse
	sort.Slice(users, func(i, j int) bool {
		var less bool
		a, b := users[i], users[j]
		switch col {
		case 0:
			less = strings.ToLower(a.Email) < strings.ToLower(b.Email)
		case 1:
			less = nodeNames[a.AssignedNodeID] < nodeNames[b.AssignedNodeID]
		case 2:
			less = a.Plan < b.Plan
		case 3:
			less = a.BandwidthUsed < b.BandwidthUsed
		case 4:
			less = a.BandwidthLimit < b.BandwidthLimit
		case 5:
			less = a.Address < b.Address
		case 6:
			less = a.CreatedAt < b.CreatedAt
		default:
			less = a.Email < b.Email
		}
		if rev {
			return !less
		}
		return less
	})

	// Preserve selection
	selRow, selCol := t.userTable.GetSelection()
	t.userTable.Clear()

	// Header
	for c, name := range userColumns {
		label := name
		if c == col {
			arrow := "▲"
			if rev {
				arrow = "▼"
			}
			label = fmt.Sprintf("%s %s", name, arrow)
		}
		cell := tview.NewTableCell(label).
			SetTextColor(colorCyan).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false).
			SetExpansion(1).
			SetAlign(tview.AlignLeft)
		cell.SetBackgroundColor(tcell.NewRGBColor(30, 30, 60))
		t.userTable.SetCell(0, c, cell)
	}

	// Data rows
	for r, user := range users {
		row := r + 1
		bgColor := tcell.NewRGBColor(20, 20, 35)
		if row%2 == 0 {
			bgColor = tcell.NewRGBColor(28, 28, 45)
		}

		nn := nodeNames[user.AssignedNodeID]
		if nn == "" {
			nn = truncate(user.AssignedNodeID, 12)
		}

		bwColor := bandwidthColor(user.BandwidthUsed, user.BandwidthLimit)
		bar := bandwidthBar(user.BandwidthUsed, user.BandwidthLimit, 10)
		bwTColor := tcell.ColorGreen
		switch bwColor {
		case "yellow":
			bwTColor = tcell.ColorYellow
		case "red":
			bwTColor = tcell.ColorRed
		}

		created := user.CreatedAt
		if len(created) > 10 {
			created = created[:10]
		}

		setCell := func(c int, text string, color tcell.Color) {
			cell := tview.NewTableCell(text).
				SetTextColor(color).
				SetExpansion(1).
				SetAlign(tview.AlignLeft).
				SetBackgroundColor(bgColor)
			t.userTable.SetCell(row, c, cell)
		}

		setCell(0, user.Email, tcell.ColorWhite)
		setCell(1, nn, colorLightGray)
		setCell(2, user.Plan, colorLightCyan)
		setCell(3, fmt.Sprintf("%s %s", bar, formatBytes(user.BandwidthUsed)), bwTColor)
		setCell(4, formatBytes(user.BandwidthLimit), colorLightGray)
		setCell(5, user.Address, colorLightGray)
		setCell(6, created, tcell.ColorGray)
	}

	if t.ui.userFilter != "" {
		t.filterBox.SetText(t.ui.userFilter)
	}

	// Restore selection — disable selectable if no data rows to prevent crashes
	maxRow := t.userTable.GetRowCount() - 1
	if maxRow < 1 {
		t.userTable.SetSelectable(false, false)
	} else {
		t.userTable.SetSelectable(true, false)
		if selRow > maxRow {
			selRow = maxRow
		}
		if selRow < 1 {
			selRow = 1
		}
		t.userTable.Select(selRow, selCol)
	}
}

// ---------------------------------------------------------------------------
// Detail modals
// ---------------------------------------------------------------------------

func (t *TUI) showNodeDetailModal() {
	row, _ := t.nodeTable.GetSelection()
	if row < 1 || row-1 >= len(t.snap.Nodes) {
		return
	}

	node := t.snap.Nodes[row-1]
	bwEntries := t.snap.NodeBandwidth[node.ID]

	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true).
		SetTitle(fmt.Sprintf(" Node: %s ", node.Name)).
		SetTitleColor(colorCyan).
		SetBorderColor(colorCyan).
		SetBackgroundColor(tcell.NewRGBColor(15, 15, 30))

	sColor := statusColor(node.Status)
	ownerStr := "[gray]unassigned[-]"
	if node.OwnerID != "" {
		ownerStr = fmt.Sprintf("[white]%s[-]", node.OwnerID)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, " [bold][cyan]Node Details[-]\n\n")
	fmt.Fprintf(&sb, "  [gray]ID:[-]         [white]%s[-]\n", node.ID)
	fmt.Fprintf(&sb, "  [gray]Name:[-]       [white]%s[-]\n", node.Name)
	fmt.Fprintf(&sb, "  [gray]IP:[-]         [white]%s[-]\n", node.IP)
	fmt.Fprintf(&sb, "  [gray]Region:[-]     [white]%s[-]\n", node.Region)
	fmt.Fprintf(&sb, "  [gray]Endpoint:[-]   [white]%s[-]\n", node.Endpoint)
	fmt.Fprintf(&sb, "  [gray]Public Key:[-] [white]%s[-]\n", truncate(node.PublicKey, 44))
	fmt.Fprintf(&sb, "  [gray]Status:[-]     [%s]%s[-]\n", sColor, strings.ToUpper(node.Status))
	fmt.Fprintf(&sb, "  [gray]Owner:[-]      %s\n", ownerStr)
	peerCount := len(bwEntries)
	if node.MaxPeers > 0 {
		fmt.Fprintf(&sb, "  [gray]Peers:[-]      [white]%d / %d[-]\n", peerCount, node.MaxPeers)
	} else {
		fmt.Fprintf(&sb, "  [gray]Peers:[-]      [white]%d[-]\n", peerCount)
	}
	fmt.Fprintln(&sb)

	if len(bwEntries) > 0 {
		fmt.Fprintf(&sb, " [bold][cyan]Per-Peer Bandwidth[-]\n\n")
		fmt.Fprintf(&sb, "  [cyan]%-44s  %12s  %12s[-]\n", "Public Key", "Received", "Sent")
		fmt.Fprintf(&sb, "  [gray]%s[-]\n", strings.Repeat("─", 72))
		for _, e := range bwEntries {
			fmt.Fprintf(&sb, "  [white]%-44s[-]  [lightcyan]%12s[-]  [lightcyan]%12s[-]\n",
				truncate(e.PublicKey, 44), formatBytes(e.TotalReceived), formatBytes(e.TotalSent))
		}
	} else {
		fmt.Fprintf(&sb, " [gray]No bandwidth data available[-]\n")
	}

	fmt.Fprintf(&sb, "\n [gray]Press Esc or Enter to close[-]")
	tv.SetText(sb.String())

	modal := makeModal(tv, 80, 24)
	t.ui.showNodeDetail = true
	t.rootPages.AddPage("nodeDetail", modal, true, true)
}

func (t *TUI) showUserDetailModal() {
	row, _ := t.userTable.GetSelection()
	if row < 1 {
		return
	}

	users := t.filteredUsers()
	idx := row - 1
	if idx >= len(users) {
		return
	}
	user := users[idx]

	nodeName := user.AssignedNodeID
	for _, n := range t.snap.Nodes {
		if n.ID == user.AssignedNodeID {
			nodeName = n.Name
			break
		}
	}

	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true).
		SetTitle(fmt.Sprintf(" User: %s ", user.Email)).
		SetTitleColor(colorCyan).
		SetBorderColor(colorCyan).
		SetBackgroundColor(tcell.NewRGBColor(15, 15, 30))

	bwColor := bandwidthColor(user.BandwidthUsed, user.BandwidthLimit)
	bar := bandwidthBar(user.BandwidthUsed, user.BandwidthLimit, 20)
	pct := 0
	if user.BandwidthLimit > 0 {
		pct = int(user.BandwidthUsed * 100 / user.BandwidthLimit)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, " [bold][cyan]User Details[-]\n\n")
	fmt.Fprintf(&sb, "  [gray]ID:[-]              [white]%s[-]\n", user.ID)
	fmt.Fprintf(&sb, "  [gray]Email:[-]           [white]%s[-]\n", user.Email)
	fmt.Fprintf(&sb, "  [gray]Plan:[-]            [lightcyan]%s[-]\n", user.Plan)
	fmt.Fprintf(&sb, "  [gray]Address:[-]         [white]%s[-]\n", user.Address)
	fmt.Fprintf(&sb, "  [gray]Assigned Node:[-]   [white]%s[-]\n", nodeName)
	fmt.Fprintf(&sb, "  [gray]Public Key:[-]      [white]%s[-]\n", truncate(user.PublicKey, 44))
	fmt.Fprintf(&sb, "  [gray]Created:[-]         [white]%s[-]\n\n", user.CreatedAt)
	fmt.Fprintf(&sb, "  [gray]Bandwidth:[-]       [%s]%s[-] [white]%s / %s[-] [gray](%d%%)[-]\n",
		bwColor, bar, formatBytes(user.BandwidthUsed), formatBytes(user.BandwidthLimit), pct)

	// Show network rules
	rules := t.fetchUserRules(user.ID)
	if len(rules) > 0 {
		names := make([]string, len(rules))
		for i, r := range rules {
			rule := r.(map[string]any)
			names[i] = fmt.Sprintf("%s (%s)", rule["name"], rule["network"])
		}
		fmt.Fprintf(&sb, "\n  [gray]Bypass Rules:[-]    [yellow]%s[-]\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintf(&sb, "\n  [gray]Bypass Rules:[-]    [white]none (full tunnel)[-]\n")
	}

	fmt.Fprintf(&sb, "\n [gray]Press Esc or Enter to close[-]")
	tv.SetText(sb.String())

	modal := makeModal(tv, 70, 18)
	t.ui.showUserDetail = true
	t.rootPages.AddPage("userDetail", modal, true, true)
}

func (t *TUI) fetchUserRules(userID string) []any {
	var result []any
	err := t.api.get(fmt.Sprintf("/api/users/%s/rules", userID), &result)
	if err != nil {
		return nil
	}
	return result
}

func (t *TUI) showHelpOverlay() {
	tv := tview.NewTextView().SetDynamicColors(true)
	tv.SetBorder(true).
		SetTitle(" Keyboard Shortcuts ").
		SetTitleColor(colorCyan).
		SetBorderColor(colorCyan).
		SetBackgroundColor(tcell.NewRGBColor(15, 15, 30))

	help := ` [bold][cyan]Navigation[-]
  [yellow]1[-] / [yellow]2[-] / [yellow]3[-]    Switch tabs (Dashboard / Nodes / Users)
  [yellow]Tab[-]          Next tab
  [yellow]↑ ↓[-]          Navigate table rows

 [bold][cyan]Tables[-]
  [yellow]s[-]            Cycle sort column
  [yellow]r[-]            Reverse sort order
  [yellow]Enter[-]        Open detail modal
  [yellow]/[-]            Filter (Users tab)
  [yellow]Esc[-]          Clear filter / close modal

 [bold][cyan]General[-]
  [yellow]?[-]            Toggle this help
  [yellow]q[-] / [yellow]Ctrl+C[-]  Quit

 [gray]Press any key to close[-]`
	tv.SetText(help)

	modal := makeModal(tv, 56, 20)
	t.ui.showHelp = true
	t.rootPages.AddPage("help", modal, true, true)
}

func makeModal(content tview.Primitive, width, height int) *tview.Flex {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(content, height, 0, true).
			AddItem(nil, 0, 1, false), width, 0, true).
		AddItem(nil, 0, 1, false)
}

// ---------------------------------------------------------------------------
// Data polling — runs on its own goroutine, sends snapshots via channel
// ---------------------------------------------------------------------------

func (t *TUI) pollData(snapCh chan<- Snapshot) {
	// Fetch immediately
	snapCh <- t.api.fetchSnapshot()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		snapCh <- t.api.fetchSnapshot()
	}
}

func (t *TUI) applySnapshot(snap Snapshot) {
	t.snap = snap
	t.updateHeader()
	t.updateTabBar()
	t.updateFooter()

	// Only refresh the active tab to avoid mutating off-screen tables
	switch t.ui.activeTab {
	case 0:
		t.refreshDashboard()
	case 1:
		t.refreshNodesTable()
	case 2:
		t.refreshUsersTable()
	case 3:
		t.refreshSecurityView()
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	tui := NewTUI()

	// Force-quit signal handler — hard exit, don't wait for app.Stop()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		// Hard exit: restore terminal and quit immediately
		tui.app.Stop()
		// If Stop() hangs, force exit after 1 second
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}()

	// Snapshot channel — poller sends, UI receives via QueueUpdateDraw
	snapCh := make(chan Snapshot, 1)
	go tui.pollData(snapCh)

	// Receive snapshots and apply on the UI goroutine
	go func() {
		for snap := range snapCh {
			s := snap // capture for closure
			tui.app.QueueUpdateDraw(func() {
				tui.applySnapshot(s)
			})
		}
	}()

	if err := tui.app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
