package js

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type SecretFinding struct {
	Type      string                 `json:"type"`
	Value     string                 `json:"value"`
	IsValid   bool                   `json:"is_valid"`
	Validated bool                   `json:"validated"`
	RiskLevel string                 `json:"risk_level"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

type ValidationResult struct {
	IsValid  bool
	Metadata map[string]interface{}
	Error    string
}

type SecretValidator struct {
	patterns map[string]*SecretProfile
	client   *http.Client
}

type SecretProfile struct {
	Regex      *regexp.Regexp
	RiskLevel  string
	Validation func(context.Context, string, *http.Client) *ValidationResult
}

func NewSecretValidator() *SecretValidator {
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	sv := &SecretValidator{
		client: client,
		patterns: map[string]*SecretProfile{
			"AWS_KEY": {
				Regex:     regexp.MustCompile(`\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
				RiskLevel: "CRITICAL",
				Validation: func(ctx context.Context, s string, _ *http.Client) *ValidationResult {
					return validateAWSKey(ctx, s)
				},
			},
			"GITHUB_TOKEN": {
				Regex:     regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`),
				RiskLevel: "HIGH",
				Validation: validateGitHubToken,
			},
			"STRIPE_KEY": {
				Regex:     regexp.MustCompile(`\b(sk|pk)_(test|live)_[A-Za-z0-9]{24,}\b`),
				RiskLevel: "CRITICAL",
				Validation: validateStripeKey,
			},
			"SLACK_TOKEN": {
				Regex:     regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`),
				RiskLevel: "HIGH",
				Validation: validateSlackToken,
			},
			"DIGITALOCEAN_TOKEN": {
				Regex:     regexp.MustCompile(`\b[0-9a-f]{64}\b`),
				RiskLevel: "HIGH",
				Validation: validateDigitalOceanToken,
			},
			"CLOUDFLARE_TOKEN": {
				Regex:     regexp.MustCompile(`\b[0-9A-Za-z\-\_]{40,}\b`),
				RiskLevel: "HIGH",
				Validation: validateCloudflareKey,
			},
			"DISCORD_TOKEN": {
				Regex:     regexp.MustCompile(`\b(mfa\.[A-Za-z0-9\-_]{84}|[A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27})\b`),
				RiskLevel: "HIGH",
				Validation: validateDiscordToken,
			},
			"NPM_TOKEN": {
				Regex:     regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`),
				RiskLevel: "HIGH",
				Validation: validateNpmToken,
			},
			"MAILGUN_KEY": {
				Regex:     regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32,}\b`),
				RiskLevel: "HIGH",
				Validation: validateMailgunKey,
			},
			"TWILIO_SID": {
				Regex:     regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`),
				RiskLevel: "MEDIUM",
				Validation: validateTwilioSID,
			},
			"JWT_SECRET": {
				Regex:     regexp.MustCompile(`(?i)\b(jwt|jwt_secret|jwtKey)\b[^\n]{0,50}`),
				RiskLevel: "MEDIUM",
				Validation: validateJWTSecret,
			},
			"KUBE_TOKEN": {
				Regex:     regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
				RiskLevel: "HIGH",
				Validation: validateKubeConfig,
			},
			"SSH_KEY": {
				Regex:     regexp.MustCompile(`(?s)-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----.*?-----END .*? PRIVATE KEY-----`),
				RiskLevel: "HIGH",
				Validation: validateSSHKey,
			},
			"AZURE_BEARER": {
				Regex:     regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
				RiskLevel: "HIGH",
				Validation: validateAzureCert,
			},
			"GENERIC_API_TOKEN": {
				Regex:     regexp.MustCompile(`\b([A-Za-z0-9_\-]{32,64})\b`),
				RiskLevel: "LOW",
				Validation: validateGenericAPIToken,
			},
		},
	}
	return sv
}

func (v *SecretValidator) ScanContent(content []byte, sourceURL string) []SecretFinding {
	var findings []SecretFinding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	text := string(content)
	for secretType, profile := range v.patterns {
		matches := profile.Regex.FindAllString(text, -1)
		for _, match := range matches {
			res := profile.Validation(ctx, match, v.client)
			f := SecretFinding{
				Type:      secretType,
				Value:     match,
				IsValid:   res.IsValid,
				Validated: res.Error == "" || res.IsValid,
				RiskLevel: profile.RiskLevel,
				Source:    sourceURL,
				Metadata:  res.Metadata,
				Error:     res.Error,
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func validateAWSKey(_ context.Context, keyID string) *ValidationResult {
	if len(keyID) < 4 {
		return &ValidationResult{Error: "invalid key id"}
	}
	prefix := keyID[:4]
	return &ValidationResult{
		IsValid:  false,
		Metadata: map[string]interface{}{"format_ok": true, "prefix": prefix},
		Error:    "passive check only (no secret to sign STS)",
	}
}

func validateGitHubToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+token)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		var result struct {
			Login string `json:"login"`
		}
		_ = json.Unmarshal(body, &result)
		return &ValidationResult{
			IsValid: true,
			Metadata: map[string]interface{}{
				"user":   result.Login,
				"scopes": resp.Header.Get("X-OAuth-Scopes"),
			},
		}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateStripeKey(ctx context.Context, key string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://api.stripe.com/v1/balance", nil)
	req.SetBasicAuth(key, "")
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &ValidationResult{IsValid: true}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateSlackToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		var res struct{ OK bool `json:"ok"` }
		_ = json.Unmarshal(body, &res)
		if res.OK {
			return &ValidationResult{IsValid: true}
		}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateGoogleOAuth(ctx context.Context, key string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+url.QueryEscape(key),
		nil,
	)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var j map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		return &ValidationResult{IsValid: true, Metadata: j}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateFirebaseKey(ctx context.Context, key string, client *http.Client) *ValidationResult {
	payload := strings.NewReader(`{"returnSecureToken":true}`)
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="+url.QueryEscape(key),
		payload)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var j map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		return &ValidationResult{IsValid: true, Metadata: j}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateHerokuKey(ctx context.Context, key string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.heroku.com/account", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var j map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		return &ValidationResult{IsValid: true, Metadata: j}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateTwilioSID(_ context.Context, sid string, _ *http.Client) *ValidationResult {
	ok := regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`).MatchString(sid)
	if ok {
		return &ValidationResult{IsValid: false, Metadata: map[string]interface{}{"format_ok": true}}
	}
	return &ValidationResult{Error: "invalid format"}
}

func validateDigitalOceanToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.digitalocean.com/v2/account", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var j struct {
			Account struct {
				Email string `json:"email"`
			} `json:"account"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&j)
		return &ValidationResult{IsValid: true, Metadata: map[string]interface{}{"email": j.Account.Email}}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateJWTSecret(_ context.Context, secret string, _ *http.Client) *ValidationResult {
	if len(strings.TrimSpace(secret)) >= 8 {
		return &ValidationResult{IsValid: false, Metadata: map[string]interface{}{"length": len(secret)}}
	}
	return &ValidationResult{Error: "too short to be a useful secret"}
}

func validateKubeConfig(_ context.Context, token string, _ *http.Client) *ValidationResult {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		return &ValidationResult{IsValid: false, Metadata: map[string]interface{}{"looks_like_jwt": true}}
	}
	return &ValidationResult{Error: "not a JWT-like token"}
}

func validateNpmToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/npm/v1/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &ValidationResult{IsValid: true}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateCloudflareKey(ctx context.Context, key string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		var j struct{ Success bool `json:"success"` }
		_ = json.NewDecoder(resp.Body).Decode(&j)
		if j.Success {
			return &ValidationResult{IsValid: true}
		}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateDiscordToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/v9/users/@me", nil)
	req.Header.Set("Authorization", "Bot "+token)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &ValidationResult{IsValid: true}
	}
	req2, _ := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/v9/users/@me", nil)
	req2.Header.Set("Authorization", token)
	resp2, err := client.Do(req2)
	if err == nil && resp2.StatusCode == 200 {
		resp2.Body.Close()
		return &ValidationResult{IsValid: true}
	}
	if resp2 != nil {
		resp2.Body.Close()
	}
	return &ValidationResult{Error: "unauthorized"}
}

func validateMailgunKey(ctx context.Context, key string, client *http.Client) *ValidationResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.mailgun.net/v3/domains", nil)
	req.SetBasicAuth("api", key)
	resp, err := client.Do(req)
	if err != nil {
		return &ValidationResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return &ValidationResult{IsValid: true}
	}
	return &ValidationResult{Error: fmt.Sprintf("status %d", resp.StatusCode)}
}

func validateSSHKey(_ context.Context, key string, _ *http.Client) *ValidationResult {
	ok := regexp.MustCompile(`(?s)^-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----.*-----END .* PRIVATE KEY-----\s*$`).MatchString(strings.TrimSpace(key))
	if ok {
		return &ValidationResult{IsValid: false, Metadata: map[string]interface{}{"format_ok": true}}
	}
	return &ValidationResult{Error: "invalid key format"}
}

func validateAzureCert(_ context.Context, bearer string, _ *http.Client) *ValidationResult {
	parts := strings.Split(bearer, ".")
	if len(parts) == 3 {
		return &ValidationResult{IsValid: false, Metadata: map[string]interface{}{"looks_like_jwt": true}}
	}
	return &ValidationResult{Error: "invalid bearer format"}
}

func validateGenericAPIToken(ctx context.Context, token string, client *http.Client) *ValidationResult {
	if strings.TrimSpace(token) == "" {
		return &ValidationResult{Error: "empty token"}
	}
	endpoints := []string{
		"https://api.example.com/v1/user",
		"https://api.example.com/v1/account",
		"https://api.example.com/me",
	}
	for _, endpoint := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, "HEAD", endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return &ValidationResult{IsValid: true}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return &ValidationResult{Error: errors.New("no common endpoint accepted token").Error()}
}
