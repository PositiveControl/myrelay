package api

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/m7s/vpn/internal/bypass"
	"github.com/m7s/vpn/internal/db"
	"github.com/m7s/vpn/internal/models"
	"github.com/m7s/vpn/internal/wireguard"
)

// handleOnboardPage serves the onboarding HTML page for a given token.
func (s *Server) handleOnboardPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	_, _, errMsg := s.validateOnboardingToken(token)
	if errMsg != "" {
		s.renderOnboardError(w, errMsg)
		return
	}

	data := map[string]string{
		"Token": token,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := onboardTmpl.Execute(w, data); err != nil {
		log.Printf("Failed to render onboarding page: %v", err)
	}
}

// handleOnboardConfig serves the WireGuard .conf file download.
func (s *Server) handleOnboardConfig(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	_, user, errMsg := s.validateOnboardingToken(token)
	if errMsg != "" {
		s.renderOnboardError(w, errMsg)
		return
	}

	clientConfig, err := s.buildClientConfig(user)
	if err != nil {
		s.renderOnboardError(w, "Failed to generate your VPN configuration. Please contact your administrator.")
		return
	}

	// Mark token as used (but allow re-downloads).
	_ = s.db.MarkOnboardingTokenUsed(token)

	// Name the file after the node's region for a friendly tunnel name in WireGuard.
	filename := "vpn-config.conf"
	node, err2 := s.db.GetNode(user.AssignedNodeID)
	if err2 == nil && node != nil {
		name := friendlyTunnelName(node.Region)
		if name != "" {
			filename = name + ".conf"
		}
	}

	w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	fmt.Fprint(w, clientConfig)
}

// handleOnboardQR serves the WireGuard config as a QR code PNG image.
func (s *Server) handleOnboardQR(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	_, user, errMsg := s.validateOnboardingToken(token)
	if errMsg != "" {
		http.Error(w, "Invalid or expired link", http.StatusNotFound)
		return
	}

	clientConfig, err := s.buildClientConfig(user)
	if err != nil {
		http.Error(w, "Failed to generate config", http.StatusInternalServerError)
		return
	}

	png, err := qrcode.Encode(clientConfig, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

var tunnelNames = map[string]string{
	"hil":     "VPN-Oregon",
	"ash":     "VPN-Virginia",
	"nbg1":    "VPN-Germany",
	"fsn1":    "VPN-Germany",
	"hel1":    "VPN-Finland",
	"sin":     "VPN-Singapore",
	"us-west": "VPN-Oregon",
	"us-east": "VPN-Virginia",
	"eu-fin":  "VPN-Finland",
	"eu-de":   "VPN-Germany",
	"ap-sgp":  "VPN-Singapore",
}

func friendlyTunnelName(region string) string {
	if name, ok := tunnelNames[region]; ok {
		return name
	}
	if region != "" {
		return "VPN-" + region
	}
	return ""
}

// buildClientConfig generates the WireGuard client configuration for a user.
func (s *Server) buildClientConfig(user *models.User) (string, error) {
	node, err := s.db.GetNode(user.AssignedNodeID)
	if err != nil || node == nil {
		return "", fmt.Errorf("node not found")
	}

	ip := user.Address
	if len(ip) > 3 && ip[len(ip)-3:] == "/32" {
		ip = ip[:len(ip)-3] + "/24"
	}

	override, err := s.db.GetBypassOverride(user.ID)
	if err != nil {
		log.Printf("Failed to get bypass override for user %s: %v", user.ID, err)
	}
	allowedIPs, err := bypass.ComputeAllowedIPsForUser(user.Plan, override)
	if err != nil {
		log.Printf("Failed to compute AllowedIPs for user %s: %v", user.ID, err)
		allowedIPs = "0.0.0.0/0"
	}

	return wireguard.GeneratePeerConfig(wireguard.PeerConfig{
		PrivateKey: user.PrivateKey,
		Address:    ip,
		DNS:        "1.1.1.1, 8.8.8.8",
		PublicKey:  node.PublicKey,
		Endpoint:   node.WireGuardEndpoint(),
		AllowedIPs: allowedIPs,
	})
}

// validateOnboardingToken checks the token and returns the token record, user,
// and an error message string (empty string means valid).
func (s *Server) validateOnboardingToken(token string) (*db.OnboardingToken, *models.User, string) {
	tok, err := s.db.GetOnboardingToken(token)
	if err != nil {
		log.Printf("DB error looking up onboarding token: %v", err)
		return nil, nil, "Something went wrong. Please try again or contact your administrator."
	}
	if tok == nil {
		return nil, nil, "This onboarding link is not valid. Please check the link or contact your administrator."
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		return nil, nil, "This onboarding link has expired. Please contact your administrator for a new one."
	}

	user, err := s.db.GetUser(tok.UserID)
	if err != nil || user == nil {
		return nil, nil, "Your account could not be found. Please contact your administrator."
	}

	return tok, user, ""
}

// renderOnboardError renders a friendly HTML error page.
func (s *Server) renderOnboardError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK) // Don't show scary HTTP errors to non-technical users
	data := map[string]string{"Message": message}
	if err := onboardErrorTmpl.Execute(w, data); err != nil {
		log.Printf("Failed to render onboarding error page: %v", err)
	}
}

var onboardErrorTmpl = template.Must(template.New("onboard_error").Parse(onboardErrorHTML))

var onboardTmpl = template.Must(template.New("onboard").Parse(onboardHTML))

const onboardErrorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Setup</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f0f4f8;color:#1a202c;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);padding:40px 32px;max-width:480px;width:100%;text-align:center}
.icon{font-size:48px;margin-bottom:16px}
h1{font-size:22px;margin-bottom:16px;color:#e53e3e}
p{font-size:18px;line-height:1.6;color:#4a5568}
</style>
</head>
<body>
<div class="card">
<div class="icon">&#9888;&#65039;</div>
<h1>Oops!</h1>
<p>{{.Message}}</p>
</div>
</body>
</html>`

const onboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Set Up Your VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:#f0f4f8;color:#1a202c;min-height:100vh;padding:0;
  -webkit-text-size-adjust:100%;
}
.container{max-width:520px;margin:0 auto;padding:24px 20px 48px}
.header{text-align:center;padding:32px 0 24px}
.shield{font-size:56px;margin-bottom:12px;display:block}
h1{font-size:26px;font-weight:700;color:#1a365d;margin-bottom:8px}
.subtitle{font-size:18px;color:#4a5568;line-height:1.5}
.divider{height:1px;background:linear-gradient(to right,transparent,#cbd5e0,transparent);margin:28px 0}
.step{margin-bottom:8px}
.step-number{
  display:inline-flex;align-items:center;justify-content:center;
  width:36px;height:36px;border-radius:50%;
  background:#ebf4ff;color:#2b6cb0;font-weight:700;font-size:18px;
  margin-bottom:12px;
}
.step h2{font-size:22px;font-weight:600;color:#2d3748;margin-bottom:12px}
.step p{font-size:18px;line-height:1.6;color:#4a5568;margin-bottom:16px}
.btn{
  display:block;width:100%;padding:18px 24px;border:none;border-radius:14px;
  font-size:19px;font-weight:600;text-align:center;text-decoration:none;
  cursor:pointer;transition:transform 0.1s,box-shadow 0.1s;
  -webkit-tap-highlight-color:transparent;
}
.btn:active{transform:scale(0.98)}
.btn-blue{background:#3182ce;color:#fff;box-shadow:0 4px 14px rgba(49,130,206,0.4)}
.btn-blue:hover{background:#2b6cb0}
.btn-green{background:#38a169;color:#fff;box-shadow:0 4px 14px rgba(56,161,105,0.4)}
.btn-green:hover{background:#2f855a}
.skip{display:block;text-align:center;margin-top:12px;font-size:16px;color:#718096;text-decoration:none}
.skip:hover{color:#4a5568}
.hint{
  background:#f7fafc;border:1px solid #e2e8f0;border-radius:12px;
  padding:16px 20px;margin-top:16px;font-size:16px;line-height:1.6;color:#4a5568;
}
.connect-hint{
  background:#f0fff4;border:1px solid #c6f6d5;border-radius:12px;
  padding:20px;font-size:18px;line-height:1.7;color:#276749;text-align:center;
}
.ios-step{
  display:flex;align-items:flex-start;gap:14px;
  background:#fff;border:1px solid #e2e8f0;border-radius:12px;
  padding:16px;margin-top:12px;
}
.ios-step-num{
  flex-shrink:0;width:36px;height:36px;border-radius:50%;
  background:#ebf8ff;color:#2b6cb0;font-weight:700;font-size:15px;
  display:flex;align-items:center;justify-content:center;
}
.ios-step-text{font-size:17px;line-height:1.5;color:#2d3748}
.qr-toggle{
  display:block;width:100%;padding:16px;background:#f7fafc;border:1px solid #e2e8f0;
  border-radius:12px;font-size:17px;color:#4a5568;cursor:pointer;text-align:center;
  transition:background 0.2s;-webkit-tap-highlight-color:transparent;
}
.qr-toggle:hover{background:#edf2f7}
.qr-content{
  max-height:0;overflow:hidden;transition:max-height 0.4s ease,opacity 0.3s ease;
  opacity:0;text-align:center;
}
.qr-content.open{max-height:500px;opacity:1;margin-top:16px}
.qr-content img{border-radius:12px;border:1px solid #e2e8f0;margin-bottom:12px}
.qr-content p{font-size:16px;color:#718096;line-height:1.5}
.footer{text-align:center;margin-top:32px;font-size:15px;color:#a0aec0}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <span class="shield">&#128272;</span>
  <h1>Welcome to Your VPN!</h1>
  <p class="subtitle">Setting up takes about 2 minutes.</p>
</div>

<div class="divider"></div>

<div class="step">
  <span class="step-number">1</span>
  <h2>Install WireGuard</h2>
  <p>First, download the free WireGuard app on your device.</p>
  <a id="store-link" href="https://www.wireguard.com/install/" class="btn btn-blue">Download WireGuard</a>
  <a href="#step2" class="skip">Already installed? Skip to Step 2</a>
</div>

<div class="divider"></div>

<div class="step" id="step2">
  <span class="step-number">2</span>
  <h2>Install Your VPN Profile</h2>
  <p>Tap the button below to add your VPN configuration.</p>
  <a id="install-btn" href="/onboard/{{.Token}}/config" class="btn btn-green">Tap to Install VPN</a>
  <div class="hint" id="install-hint">
    After tapping, WireGuard will ask to add the tunnel.<br>Tap <strong>&ldquo;Allow&rdquo;</strong> to finish.
  </div>
  <div id="ios-steps" style="display:none">
    <div class="ios-step">
      <div class="ios-step-num">2a</div>
      <div class="ios-step-text">A popup asks to download &mdash; tap <strong>&ldquo;Download&rdquo;</strong></div>
    </div>
    <div class="ios-step">
      <div class="ios-step-num">2b</div>
      <div class="ios-step-text">Tap the <strong>&#9660; icon</strong> that appears in your address bar (top right)</div>
    </div>
    <div class="ios-step">
      <div class="ios-step-num">2c</div>
      <div class="ios-step-text">Tap the <strong>share icon</strong> &#65039; next to the file name<br><span style="font-size:32px">&#8686;</span></div>
    </div>
    <div class="ios-step">
      <div class="ios-step-num">2d</div>
      <div class="ios-step-text">Find and tap <strong>&ldquo;WireGuard&rdquo;</strong> in the share menu</div>
    </div>
    <div class="ios-step">
      <div class="ios-step-num">2e</div>
      <div class="ios-step-text">Tap <strong>&ldquo;Allow&rdquo;</strong> to add the VPN &#127881;</div>
    </div>
  </div>
</div>

<div class="divider"></div>

<div class="step">
  <span class="step-number">3</span>
  <h2>Connect!</h2>
  <p>Open WireGuard and tap the toggle switch next to your VPN to turn it on.</p>
  <div class="connect-hint">
    When the toggle is <strong>green</strong> and you see a &#128273; icon in your status bar, you&rsquo;re protected!
  </div>
</div>

<div class="divider"></div>

<button class="qr-toggle" onclick="toggleQR()" aria-expanded="false" aria-controls="qr-section">
  Setting up from another device? Show QR code &#9660;
</button>
<div id="qr-section" class="qr-content" role="region">
  <img src="/onboard/{{.Token}}/qr" alt="VPN QR Code" width="256" height="256">
  <p>Open WireGuard &rarr; Tap <strong>+</strong> &rarr; <strong>Create from QR code</strong> &rarr; Point your camera here</p>
</div>

<div class="footer">
  Need help? Contact your VPN administrator.
</div>

</div>

<script>
(function(){
  var link=document.getElementById('store-link');
  var ua=navigator.userAgent||'';
  var isIOS=/iPhone|iPad|iPod/i.test(ua);
  if(isIOS){
    link.href='https://apps.apple.com/app/wireguard/id1441195209';
    link.textContent='Download from App Store';
    document.getElementById('install-hint').style.display='none';
    document.getElementById('ios-hint').style.display='block';
  }else if(/Android/i.test(ua)){
    link.href='https://play.google.com/store/apps/details?id=com.wireguard.android';
    link.textContent='Download from Play Store';
  }else if(/Mac/i.test(ua)){
    link.href='https://apps.apple.com/app/wireguard/id1451685025';
    link.textContent='Download for macOS';
  }else if(/Windows/i.test(ua)){
    link.href='https://download.wireguard.com/windows-client/wireguard-installer.exe';
    link.textContent='Download for Windows';
  }
})();
function toggleQR(){
  var el=document.getElementById('qr-section');
  var btn=document.querySelector('.qr-toggle');
  var open=el.classList.toggle('open');
  btn.setAttribute('aria-expanded',open);
  btn.innerHTML=open?'Hide QR code &#9650;':'Setting up from another device? Show QR code &#9660;';
}
</script>
</body>
</html>`
