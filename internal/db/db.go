package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"

	"github.com/PositiveControl/myrelay/internal/models"
)

// DB wraps the SQLite database connection.
type DB struct {
	conn *sql.DB
}

// Open creates or opens a SQLite database at the given path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite doesn't support concurrent writes

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS nodes (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			ip          TEXT NOT NULL,
			region      TEXT NOT NULL DEFAULT '',
			public_key  TEXT NOT NULL DEFAULT '',
			endpoint    TEXT NOT NULL DEFAULT '',
			max_peers   INTEGER NOT NULL DEFAULT 50,
			current_peers INTEGER NOT NULL DEFAULT 0,
			status      TEXT NOT NULL DEFAULT 'active'
		);

		CREATE TABLE IF NOT EXISTS users (
			id               TEXT PRIMARY KEY,
			email            TEXT NOT NULL UNIQUE,
			public_key       TEXT NOT NULL DEFAULT '',
			private_key      TEXT NOT NULL DEFAULT '',
			address          TEXT NOT NULL DEFAULT '',
			assigned_node_id TEXT NOT NULL DEFAULT '',
			plan             TEXT NOT NULL DEFAULT 'standard',
			bandwidth_used   INTEGER NOT NULL DEFAULT 0,
			bandwidth_limit  INTEGER NOT NULL DEFAULT 0,
			created_at       TEXT NOT NULL DEFAULT '',
			FOREIGN KEY (assigned_node_id) REFERENCES nodes(id)
		);

		CREATE TABLE IF NOT EXISTS node_tokens (
			node_id TEXT PRIMARY KEY,
			token   TEXT NOT NULL,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS ip_counter (
			id    INTEGER PRIMARY KEY CHECK (id = 1),
			next_ip INTEGER NOT NULL DEFAULT 2
		);
		INSERT OR IGNORE INTO ip_counter (id, next_ip) VALUES (1, 2);

		CREATE TABLE IF NOT EXISTS onboarding_tokens (
			token      TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			used       BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS network_rules (
			id      TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name    TEXT NOT NULL,
			network TEXT NOT NULL,
			action  TEXT NOT NULL DEFAULT 'bypass',
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return err
	}
	log.Printf("Database migrated successfully")
	return nil
}

// --- Nodes ---

func (db *DB) CreateNode(node *models.Node) error {
	_, err := db.conn.Exec(
		`INSERT INTO nodes (id, name, ip, region, public_key, endpoint, max_peers, current_peers, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		node.ID, node.Name, node.IP, node.Region, node.PublicKey, node.Endpoint,
		node.MaxPeers, node.CurrentPeers, node.Status,
	)
	return err
}

func (db *DB) GetNode(id string) (*models.Node, error) {
	var n models.Node
	err := db.conn.QueryRow(
		`SELECT id, name, ip, region, public_key, endpoint, max_peers, current_peers, status
		 FROM nodes WHERE id = ?`, id,
	).Scan(&n.ID, &n.Name, &n.IP, &n.Region, &n.PublicKey, &n.Endpoint,
		&n.MaxPeers, &n.CurrentPeers, &n.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (db *DB) ListNodes() ([]*models.Node, error) {
	rows, err := db.conn.Query(
		`SELECT id, name, ip, region, public_key, endpoint, max_peers, current_peers, status FROM nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.Node
	for rows.Next() {
		var n models.Node
		if err := rows.Scan(&n.ID, &n.Name, &n.IP, &n.Region, &n.PublicKey, &n.Endpoint,
			&n.MaxPeers, &n.CurrentPeers, &n.Status); err != nil {
			return nil, err
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

func (db *DB) IncrementNodePeers(id string) error {
	_, err := db.conn.Exec(`UPDATE nodes SET current_peers = current_peers + 1 WHERE id = ?`, id)
	return err
}

func (db *DB) DecrementNodePeers(id string) error {
	_, err := db.conn.Exec(`UPDATE nodes SET current_peers = MAX(0, current_peers - 1) WHERE id = ?`, id)
	return err
}

// --- Users ---

func (db *DB) CreateUser(user *models.User) error {
	_, err := db.conn.Exec(
		`INSERT INTO users (id, email, public_key, private_key, address, assigned_node_id, plan, bandwidth_used, bandwidth_limit, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.PublicKey, user.PrivateKey, user.Address,
		user.AssignedNodeID, user.Plan, user.BandwidthUsed, user.BandwidthLimit,
		user.CreatedAt.Format(time.RFC3339),
	)
	return err
}

func (db *DB) GetUser(id string) (*models.User, error) {
	var u models.User
	var createdAt string
	err := db.conn.QueryRow(
		`SELECT id, email, public_key, private_key, address, assigned_node_id, plan, bandwidth_used, bandwidth_limit, created_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.PublicKey, &u.PrivateKey, &u.Address,
		&u.AssignedNodeID, &u.Plan, &u.BandwidthUsed, &u.BandwidthLimit, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &u, nil
}

func (db *DB) ListUsers() ([]*models.User, error) {
	rows, err := db.conn.Query(
		`SELECT id, email, public_key, private_key, address, assigned_node_id, plan, bandwidth_used, bandwidth_limit, created_at FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var u models.User
		var createdAt string
		if err := rows.Scan(&u.ID, &u.Email, &u.PublicKey, &u.PrivateKey, &u.Address,
			&u.AssignedNodeID, &u.Plan, &u.BandwidthUsed, &u.BandwidthLimit, &createdAt); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		users = append(users, &u)
	}
	return users, rows.Err()
}

func (db *DB) DeleteUser(id string) (*models.User, error) {
	user, err := db.GetUser(id)
	if err != nil || user == nil {
		return nil, err
	}
	_, err = db.conn.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *DB) GetUserByPublicKey(publicKey string) (*models.User, error) {
	var u models.User
	var createdAt string
	err := db.conn.QueryRow(
		`SELECT id, email, public_key, private_key, address, assigned_node_id, plan, bandwidth_used, bandwidth_limit, created_at
		 FROM users WHERE public_key = ?`, publicKey,
	).Scan(&u.ID, &u.Email, &u.PublicKey, &u.PrivateKey, &u.Address,
		&u.AssignedNodeID, &u.Plan, &u.BandwidthUsed, &u.BandwidthLimit, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &u, nil
}

func (db *DB) UpdateUserBandwidth(id string, bytesUsed int64) error {
	_, err := db.conn.Exec(`UPDATE users SET bandwidth_used = ? WHERE id = ?`, bytesUsed, id)
	return err
}

// --- Node Tokens ---

func (db *DB) SaveNodeToken(nodeID, token string) error {
	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO node_tokens (node_id, token) VALUES (?, ?)`,
		nodeID, token,
	)
	return err
}

func (db *DB) GetNodeToken(nodeID string) (string, error) {
	var token string
	err := db.conn.QueryRow(`SELECT token FROM node_tokens WHERE node_id = ?`, nodeID).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

func (db *DB) ListNodeTokens() (map[string]string, error) {
	rows, err := db.conn.Query(`SELECT node_id, token FROM node_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make(map[string]string)
	for rows.Next() {
		var nodeID, token string
		if err := rows.Scan(&nodeID, &token); err != nil {
			return nil, err
		}
		tokens[nodeID] = token
	}
	return tokens, rows.Err()
}

// --- Onboarding Tokens ---

// OnboardingToken represents a single-use onboarding link token.
type OnboardingToken struct {
	Token     string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

// CreateOnboardingToken stores a new onboarding token.
func (db *DB) CreateOnboardingToken(userID, token string, expiresAt time.Time) error {
	_, err := db.conn.Exec(
		`INSERT INTO onboarding_tokens (token, user_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, FALSE)`,
		token, userID, time.Now().UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339),
	)
	return err
}

// GetOnboardingToken retrieves a token record. Returns nil if not found.
func (db *DB) GetOnboardingToken(token string) (*OnboardingToken, error) {
	var t OnboardingToken
	var createdAt, expiresAt string
	err := db.conn.QueryRow(
		`SELECT token, user_id, created_at, expires_at, used FROM onboarding_tokens WHERE token = ?`, token,
	).Scan(&t.Token, &t.UserID, &createdAt, &expiresAt, &t.Used)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	t.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return &t, nil
}

// MarkOnboardingTokenUsed marks a token as used.
func (db *DB) MarkOnboardingTokenUsed(token string) error {
	_, err := db.conn.Exec(`UPDATE onboarding_tokens SET used = TRUE WHERE token = ?`, token)
	return err
}

// --- Network Rules ---

func (db *DB) CreateNetworkRule(rule *models.NetworkRule) error {
	_, err := db.conn.Exec(
		`INSERT INTO network_rules (id, user_id, name, network, action) VALUES (?, ?, ?, ?, ?)`,
		rule.ID, rule.UserID, rule.Name, rule.Network, rule.Action,
	)
	return err
}

func (db *DB) ListNetworkRules(userID string) ([]*models.NetworkRule, error) {
	rows, err := db.conn.Query(
		`SELECT id, user_id, name, network, action FROM network_rules WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*models.NetworkRule
	for rows.Next() {
		var r models.NetworkRule
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.Network, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, &r)
	}
	return rules, rows.Err()
}

func (db *DB) DeleteNetworkRule(id string) error {
	_, err := db.conn.Exec(`DELETE FROM network_rules WHERE id = ?`, id)
	return err
}

func (db *DB) GetNetworkRule(id string) (*models.NetworkRule, error) {
	var r models.NetworkRule
	err := db.conn.QueryRow(
		`SELECT id, user_id, name, network, action FROM network_rules WHERE id = ?`, id,
	).Scan(&r.ID, &r.UserID, &r.Name, &r.Network, &r.Action)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

// --- IP Counter ---

func (db *DB) NextIP() (uint32, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var ip uint32
	if err := tx.QueryRow(`SELECT next_ip FROM ip_counter WHERE id = 1`).Scan(&ip); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE ip_counter SET next_ip = next_ip + 1 WHERE id = 1`); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return ip, nil
}
