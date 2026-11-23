// AllowBots through a real request cycle, from a public peer: the request's
// own User-Agent reaches the API, a verified crawler passes a condition it
// otherwise meets, a spoofed or not_bot one is refused, and off sends none.

package vpndetectiongin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	vpndetectiongin "github.com/vpndetection-io/sdk-go-gin/v2"
	vpndetection "github.com/vpndetection-io/sdk-go/v5"
	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

const googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

// verdictAPI answers every address as a hosting server, with the verdict its
// table holds for the agent sent, none for an agent it does not hold.
type verdictAPI struct {
	verdicts map[string]string
	mu       sync.Mutex
	agents   []string
	sent     []bool
	server   *httptest.Server
}

func newVerdictAPI(t *testing.T, verdicts map[string]string) *verdictAPI {
	t.Helper()
	api := &verdictAPI{verdicts: verdicts}
	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent, sent := r.URL.Query()["user_agent"]
		api.mu.Lock()
		api.agents = append(api.agents, strings.Join(agent, ","))
		api.sent = append(api.sent, sent)
		api.mu.Unlock()
		body := fmt.Sprintf(`{"ip":%q,"is_vpn":false,"is_hosting":true`, strings.TrimPrefix(r.URL.Path, "/"))
		if verdict, ok := api.verdicts[strings.Join(agent, ",")]; ok && sent {
			body += fmt.Sprintf(`,"user_agent":{"agent":"Googlebot","kind":"bot","verdict":%q}`, verdict)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body+"}")
	}))
	t.Cleanup(api.server.Close)
	return api
}

type botWarnings struct {
	mu       sync.Mutex
	messages []string
}

func (w *botWarnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *botWarnings) WithAttrs([]slog.Attr) slog.Handler       { return w }
func (w *botWarnings) WithGroup(string) slog.Handler            { return w }
func (w *botWarnings) Handle(_ context.Context, record slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.messages = append(w.messages, record.Message)
	return nil
}

type botAnswer struct {
	Verdict string `json:"verdict"`
}

// Stands the README's build up on a real socket, the visitor arriving from a
// public peer through a selector since a test socket is a loopback, and asks
// it once with the User-Agent given; nil sends none.
func askAsBot(t *testing.T, api *verdictAPI, allow bool, condition middleware.Conditions, logs *botWarnings,
	agent *string) (int, botAnswer) {
	t.Helper()
	client, err := vpndetection.New(vpndetection.WithBaseURL(api.server.URL), vpndetection.WithAPIKey("key"))
	if err != nil {
		t.Fatalf("vpndetection.New: %v", err)
	}
	options := middleware.Options[*gin.Context]{
		Client: client, BlockCondition: condition, AllowBots: allow, IPSelector: fixedIP,
	}
	if logs != nil {
		options.Logger = slog.New(logs)
	}
	server := httptest.NewServer(botEngine(vpndetectiongin.Must(vpndetectiongin.Options{Options: options}),
		func(c *gin.Context) {
			out := botAnswer{}
			if lookup := vpndetectiongin.FromContext(c); lookup != nil && lookup.Result != nil &&
				lookup.Result.UserAgent != nil {
				out.Verdict = string(lookup.Result.UserAgent.Verdict)
			}
			c.JSON(http.StatusOK, out)
		}))
	t.Cleanup(server.Close)

	request, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Go's client sends its own agent unless the header is present, and an
	// empty one is left off the wire.
	request.Header.Set("User-Agent", "")
	if agent != nil {
		request.Header.Set("User-Agent", *agent)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var out botAnswer
	if response.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("response body is not one JSON document (%v): %s", err, raw)
		}
	}
	return response.StatusCode, out
}

func agentOf(s string) *string { return &s }

// botEngine is the README's mount: the middleware on a gin engine, trusting no
// proxy, in front of one route.
func botEngine(guard gin.HandlerFunc, handler gin.HandlerFunc) *gin.Engine {
	engine := gin.New()
	_ = engine.SetTrustedProxies(nil)
	engine.Use(guard)
	engine.GET("/", handler)
	return engine
}

var hostingCondition = middleware.Conditions{{"is_hosting": true}}

func TestAllowBotsSendsTheRequestsOwnUserAgent(t *testing.T) {
	api := newVerdictAPI(t, map[string]string{googlebot: "verified"})
	askAsBot(t, api, true, nil, nil, agentOf(googlebot))
	if len(api.agents) != 1 || api.agents[0] != googlebot {
		t.Errorf("the API saw user_agent %q, want the request's own", api.agents)
	}
}

func TestAllowBotsSendsNoAgentForARequestWithout(t *testing.T) {
	api := newVerdictAPI(t, nil)
	askAsBot(t, api, true, nil, nil, nil)
	if len(api.sent) != 1 || api.sent[0] {
		t.Errorf("a request with no User-Agent sent user_agent %q", api.agents)
	}
}

func TestAVerifiedCrawlerPassesAConditionItOtherwiseMeets(t *testing.T) {
	for verdict, want := range map[string]int{
		"verified": http.StatusOK, "spoofed": http.StatusForbidden, "not_bot": http.StatusForbidden,
	} {
		t.Run(verdict, func(t *testing.T) {
			api := newVerdictAPI(t, map[string]string{googlebot: verdict})
			status, out := askAsBot(t, api, true, hostingCondition, nil, agentOf(googlebot))
			if status != want {
				t.Errorf("a %s crawler on a hosting address answered %d, want %d", verdict, status, want)
			}
			if want == http.StatusOK && out.Verdict != verdict {
				t.Errorf("the handler read verdict %q, want the answer attached with %q", out.Verdict, verdict)
			}
		})
	}
}

func TestAllowBotsOffSendsNoAgentAndLetsNoCrawlerThrough(t *testing.T) {
	api := newVerdictAPI(t, map[string]string{googlebot: "verified"})
	status, _ := askAsBot(t, api, false, hostingCondition, nil, agentOf(googlebot))
	if len(api.sent) != 1 || api.sent[0] {
		t.Errorf("AllowBots off sent user_agent %q", api.agents)
	}
	if status != http.StatusForbidden {
		t.Errorf("AllowBots off answered %d, want the condition's 403", status)
	}
}

func TestAConditionOnUserAgentRefusesASpoofedCrawler(t *testing.T) {
	forged := middleware.Conditions{{"user_agent": middleware.BlockCondition{"verdict": "spoofed"}}}
	for verdict, want := range map[string]int{"spoofed": http.StatusForbidden, "verified": http.StatusOK} {
		api := newVerdictAPI(t, map[string]string{googlebot: verdict})
		if status, _ := askAsBot(t, api, true, forged, nil, agentOf(googlebot)); status != want {
			t.Errorf("{user_agent: {verdict: spoofed}} on a %s crawler answered %d, want %d", verdict, status, want)
		}
	}
}

// A keyless client is never answered a verdict: nothing is let through, and
// the middleware says so once.
func TestAnAnswerWithoutAVerdictWarnsOnce(t *testing.T) {
	api := newVerdictAPI(t, nil)
	logs := &botWarnings{}
	client, err := vpndetection.New(vpndetection.WithBaseURL(api.server.URL), vpndetection.WithoutCache())
	if err != nil {
		t.Fatalf("vpndetection.New: %v", err)
	}
	guard := vpndetectiongin.Must(vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client: client, BlockCondition: hostingCondition, AllowBots: true, IPSelector: fixedIP,
		Logger: slog.New(logs),
	}})
	server := httptest.NewServer(botEngine(guard, func(c *gin.Context) { c.Status(http.StatusOK) }))
	t.Cleanup(server.Close)
	for range 3 {
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
		request.Header.Set("User-Agent", googlebot)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("an answer without a verdict answered %d, want 403", response.StatusCode)
		}
	}
	var about int
	for _, message := range logs.messages {
		if strings.Contains(message, "user_agent") {
			about++
		}
	}
	if about != 1 {
		t.Errorf("warned %d times about the missing verdict, want once: %q", about, logs.messages)
	}
}
