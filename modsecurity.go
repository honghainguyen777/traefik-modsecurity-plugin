// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
  "bytes"
  "context"
  "crypto/tls"
  "fmt"
  "io"
  "log"
  "net"
  "net/http"
  "os"
  "sync"
  "time"
)

// Config the plugin configuration.
type Config struct {
  TimeoutMillis                  int64  `json:"timeoutMillis,omitempty"`
  DialTimeoutMillis              int64  `json:"dialTimeoutMillis,omitempty"`
  IdleConnTimeoutMillis          int64  `json:"idleConnTimeoutMillis,omitempty"`
  ModSecurityUrl                 string `json:"modSecurityUrl,omitempty"`
  JailEnabled                    bool   `json:"jailEnabled,omitempty"`
  BadRequestsThresholdCount      int    `json:"badRequestsThresholdCount,omitempty"`
  BadRequestsThresholdPeriodSecs int    `json:"badRequestsThresholdPeriodSecs,omitempty"`
  JailTimeDurationSecs           int    `json:"jailTimeDurationSecs,omitempty"`
  MaxConnsPerHost                int    `json:"maxConnsPerHost,omitempty"`
  MaxIdleConnsPerHost            int    `json:"maxIdleConnsPerHost,omitempty"`
  UnhealthyWafBackOffPeriodSecs  int    `json:"unhealthyWafBackOffPeriodSecs,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
  return &Config{
    TimeoutMillis:                  2000,
    DialTimeoutMillis:              0,
    IdleConnTimeoutMillis:          0,
    JailEnabled:                    false,
    BadRequestsThresholdCount:      25,
    BadRequestsThresholdPeriodSecs: 600,
    JailTimeDurationSecs:           600,
    MaxConnsPerHost:                4,
    MaxIdleConnsPerHost:            2,
    UnhealthyWafBackOffPeriodSecs:  0,
  }
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
  next                           http.Handler
  modSecurityUrl                 string
  name                           string
  httpClient                     *http.Client
  logger                         *log.Logger
  jailEnabled                    bool
  badRequestsThresholdCount      int
  badRequestsThresholdPeriodSecs int
  unhealthyWafBackOffPeriodSecs  int
  unhealthyWaf                   bool
  unhealthyWafMutex              sync.Mutex
  jailTimeDurationSecs           int
  jail                           map[string][]time.Time
  jailRelease                    map[string]time.Time
  jailMutex                      sync.RWMutex
}

// New creates a new Modsecurity plugin with the given configuration.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
  if len(config.ModSecurityUrl) == 0 {
    return nil, fmt.Errorf("modSecurityUrl cannot be empty")
  }

  // whole-request timeout
  var timeout time.Duration
  if config.TimeoutMillis == 0 {
    timeout = 2 * time.Second
  } else {
    timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
  }

  // dial timeout
  dialTO := 30 * time.Second
  if config.DialTimeoutMillis > 0 {
    dialTO = time.Duration(config.DialTimeoutMillis) * time.Millisecond
  }
  dialer := &net.Dialer{
    Timeout:   dialTO,
    KeepAlive: 30 * time.Second,
  }

  // idle keep-alive TTL
  idleTO := 90 * time.Second
  if config.IdleConnTimeoutMillis > 0 {
    idleTO = time.Duration(config.IdleConnTimeoutMillis) * time.Millisecond
  }

  // per-host idle-pool cap
  perHost := 2
  if config.MaxIdleConnsPerHost > 0 {
    perHost = config.MaxIdleConnsPerHost
  }

  // NEW: active-connection cap
  active := 4
  if config.MaxConnsPerHost > 0 {
    active = config.MaxConnsPerHost
  }

  transport := &http.Transport{
    MaxIdleConns:          100,
    MaxConnsPerHost:       active,
    MaxIdleConnsPerHost:   perHost,
    IdleConnTimeout:       idleTO,
    TLSHandshakeTimeout:   10 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
    TLSClientConfig: &tls.Config{
      MinVersion: tls.VersionTLS12,
    },
    ForceAttemptHTTP2: true,
    DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
      return dialer.DialContext(ctx, network, addr)
    },
  }

  return &Modsecurity{
    modSecurityUrl:                 config.ModSecurityUrl,
    next:                           next,
    name:                           name,
    httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
    logger:                         log.New(os.Stdout, "", log.LstdFlags),
    jailEnabled:                    config.JailEnabled,
    badRequestsThresholdCount:      config.BadRequestsThresholdCount,
    badRequestsThresholdPeriodSecs: config.BadRequestsThresholdPeriodSecs,
    jailTimeDurationSecs:           config.JailTimeDurationSecs,
    jail:                           make(map[string][]time.Time),
    jailRelease:                    make(map[string]time.Time),
    unhealthyWafBackOffPeriodSecs:  config.UnhealthyWafBackOffPeriodSecs,
  }, nil
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
  if isWebsocket(req) {
    a.next.ServeHTTP(rw, req)
    return
  }

  clientIP := req.RemoteAddr

  // jail check
  if a.jailEnabled {
    a.jailMutex.RLock()
    if a.isClientInJail(clientIP) {
      a.jailMutex.RUnlock()
      a.logger.Printf("client %s is jailed", clientIP)
      http.Error(rw, "Too Many Requests", http.StatusTooManyRequests)
      return
    }
    a.jailMutex.RUnlock()
  }

  // breaker check
  if a.unhealthyWaf {
    a.next.ServeHTTP(rw, req)
    return
  }

  // buffer body
  body, err := io.ReadAll(req.Body)
  if err != nil {
    a.logger.Printf("fail to read incoming request: %s", err.Error())
    http.Error(rw, "", http.StatusBadGateway)
    return
  }
  req.Body = io.NopCloser(bytes.NewReader(body))

  url := fmt.Sprintf("%s%s", a.modSecurityUrl, req.RequestURI)
  proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
  if err != nil {
    a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
    http.Error(rw, "", http.StatusBadGateway)
    return
  }
  proxyReq.Header = make(http.Header)
  for h, val := range req.Header {
    proxyReq.Header[h] = val
  }

  resp, err := a.httpClient.Do(proxyReq)
  if err != nil {
    a.markUnhealthy()
    a.next.ServeHTTP(rw, req)
    return
  }
  defer resp.Body.Close()

  if resp.StatusCode >= 500 {
    a.markUnhealthy()
  }

  if resp.StatusCode >= 400 {
    if resp.StatusCode == http.StatusForbidden && a.jailEnabled {
      a.recordOffense(clientIP)
    }
    forwardResponse(resp, rw)
    return
  }

  a.next.ServeHTTP(rw, req)
}

// markUnhealthy toggles the breaker for the configured back-off window.
func (a *Modsecurity) markUnhealthy() {
  if a.unhealthyWafBackOffPeriodSecs == 0 {
    return
  }
  a.unhealthyWafMutex.Lock()
  if !a.unhealthyWaf {
    a.unhealthyWaf = true
    back := a.unhealthyWafBackOffPeriodSecs
    a.logger.Printf("marking modsec as unhealthy for %ds", back)
    time.AfterFunc(time.Duration(back)*time.Second, func() {
      a.unhealthyWafMutex.Lock()
      a.unhealthyWaf = false
      a.unhealthyWafMutex.Unlock()
      a.logger.Printf("modsec unhealthy backoff expired")
    })
  }
  a.unhealthyWafMutex.Unlock()
}

func isWebsocket(req *http.Request) bool {
  for _, header := range req.Header["Upgrade"] {
    if header == "websocket" {
      return true
    }
  }
  return false
}

func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
  for k, vv := range resp.Header {
    for _, v := range vv {
      rw.Header().Add(k, v)
    }
  }
  rw.WriteHeader(resp.StatusCode)
  io.Copy(rw, resp.Body)
}

func (a *Modsecurity) recordOffense(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	now := time.Now()
	// Remove offenses that are older than the threshold period
	if offenses, exists := a.jail[clientIP]; exists {
		var newOffenses []time.Time
		for _, offense := range offenses {
			if now.Sub(offense) <= time.Duration(a.badRequestsThresholdPeriodSecs)*time.Second {
				newOffenses = append(newOffenses, offense)
			}
		}
		a.jail[clientIP] = newOffenses
	}

	// Record the new offense
	a.jail[clientIP] = append(a.jail[clientIP], now)

	// Check if the client should be jailed
	if len(a.jail[clientIP]) >= a.badRequestsThresholdCount {
		a.logger.Printf("client %s reached threshold, putting in jail", clientIP)
		a.jailRelease[clientIP] = now.Add(time.Duration(a.jailTimeDurationSecs) * time.Second)
	}
}

func (a *Modsecurity) isClientInJail(clientIP string) bool {
	if releaseTime, exists := a.jailRelease[clientIP]; exists {
		if time.Now().Before(releaseTime) {
			return true
		}
		a.releaseFromJail(clientIP)
	}
	return false
}

func (a *Modsecurity) releaseFromJail(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	delete(a.jail, clientIP)
	delete(a.jailRelease, clientIP)
	a.logger.Printf("client %s released from jail", clientIP)
}
