package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/m7s/vpn/internal/bypass"
	"github.com/m7s/vpn/internal/db"
	"github.com/m7s/vpn/internal/httputil"
)

// BypassHandler handles HTTP requests for bypass rule management.
type BypassHandler struct {
	db *db.DB
}

// NewBypassHandler creates a handler backed by the database.
func NewBypassHandler(database *db.DB) *BypassHandler {
	return &BypassHandler{db: database}
}

// ListRules handles GET /api/bypass/rules.
func (h *BypassHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules := bypass.ListRules()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"rules":    rules,
		"defaults": bypass.PlanDefaults,
	})
}

// GetUserBypass handles GET /api/users/{id}/bypass.
func (h *BypassHandler) GetUserBypass(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	user, err := h.db.GetUser(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	override, err := h.db.GetBypassOverride(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	ruleNames := bypass.ResolveRuleNames(user.Plan, override)
	source := "plan_default"
	if override != nil {
		source = "override"
	}

	allowedIPs, err := bypass.ComputeAllowedIPsForUser(user.Plan, override)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to compute allowed IPs")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":     id,
		"plan":        user.Plan,
		"source":      source,
		"rule_names":  ruleNames,
		"allowed_ips": allowedIPs,
	})
}

// SetUserBypass handles PUT /api/users/{id}/bypass.
func (h *BypassHandler) SetUserBypass(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	user, err := h.db.GetUser(id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if user == nil {
		httputil.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		RuleNames *string `json:"rule_names"` // comma-separated, or null to reset
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RuleNames == nil {
		// Reset to plan defaults
		if err := h.db.ClearBypassOverride(id); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to clear override")
			return
		}
	} else {
		// Set override
		if err := h.db.SetBypassOverride(id, *req.RuleNames); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to set override")
			return
		}
	}

	// Return the new effective state
	h.GetUserBypass(w, r)
}
