package models

import "time"

// Plan represents a user's subscription tier.
type Plan string

const (
	PlanStandard Plan = "standard"
	PlanPremium  Plan = "premium"
)

// BandwidthLimits maps plans to their monthly bandwidth limits in bytes.
var BandwidthLimits = map[Plan]int64{
	PlanStandard: 100 * 1024 * 1024 * 1024, // 100 GB
	PlanPremium:  1024 * 1024 * 1024 * 1024, // 1 TB
}

// User represents a VPN service subscriber.
type User struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	PublicKey      string    `json:"public_key"`
	PrivateKey     string    `json:"private_key"`
	Address        string    `json:"address"`
	AssignedNodeID string    `json:"assigned_node_id"`
	Plan           Plan      `json:"plan"`
	BandwidthUsed  int64     `json:"bandwidth_used"`
	BandwidthLimit int64     `json:"bandwidth_limit"`
	CreatedAt      time.Time `json:"created_at"`
}

// IsOverLimit returns true if the user has exceeded their bandwidth allocation.
func (u *User) IsOverLimit() bool {
	return u.BandwidthUsed >= u.BandwidthLimit
}

// BandwidthRemainingBytes returns how many bytes the user has left.
func (u *User) BandwidthRemainingBytes() int64 {
	remaining := u.BandwidthLimit - u.BandwidthUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// NewUser creates a user with default bandwidth limits for their plan.
func NewUser(id, email string, plan Plan) *User {
	limit, ok := BandwidthLimits[plan]
	if !ok {
		limit = BandwidthLimits[PlanStandard]
	}
	return &User{
		ID:             id,
		Email:          email,
		Plan:           plan,
		BandwidthUsed:  0,
		BandwidthLimit: limit,
		CreatedAt:      time.Now(),
	}
}
