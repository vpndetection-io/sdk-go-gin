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
	"slices"
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

const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/151.0.0.0 Safari/537.36"

func crawlerAgent(n int) string {
	return fmt.Sprintf("Mozilla/5.0 (compatible; Examplebot/%d.0)", n)
}

// crawlerOrigin answers every address as a bot's, and a lookup that carries a
// user agent a verified verdict for it. With verified set, the answer's bot
// member also says its operator vouches for the address.
type crawlerOrigin struct {
	verified bool
	mu       sync.Mutex
	agents   []string
	sent     []bool
}

func (o *crawlerOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent, sent := r.URL.Query()["user_agent"]
	o.mu.Lock()
	o.agents = append(o.agents, strings.Join(agent, ","))
	o.sent = append(o.sent, sent)
	o.mu.Unlock()
	body := fmt.Sprintf(`{"ip":%q,"is_vpn":false,"is_bot":true`, strings.TrimPrefix(r.URL.Path, "/"))
	if o.verified {
		body += `,"bot":{"verified":true}`
	}
	if sent {
		body += `,"user_agent":{"agent":"Examplebot","kind":"bot","verdict":"verified"}`
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body+"}")
}

// What the origin handler behind the middleware saw: a request that reached it
// at all, so a middleware replaced by a no-op fails an assertion on it.
type reached struct {
	Attached bool   `json:"attached"`
	Bogon    bool   `json:"bogon"`
	Verdict  string `json:"verdict"`
}

type reply struct {
	status int
	reached
}

// askEach stands the middleware up with AllowBots on a real socket, every
// request arriving from peer through a selector and no answer cached, and asks
// with each User-Agent in turn; an empty one sends none.
func askEach(t *testing.T, origin http.Handler, peer string, condition middleware.Conditions,
	action middleware.MissingFieldAction, agents ...string) []reply {
	t.Helper()
	api := httptest.NewServer(origin)
	t.Cleanup(api.Close)
	client, err := vpndetection.New(vpndetection.WithBaseURL(api.URL), vpndetection.WithAPIKey("key"),
		vpndetection.WithoutCache())
	if err != nil {
		t.Fatalf("vpndetection.New: %v", err)
	}
	guard := vpndetectiongin.Must(vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client: client, BlockCondition: condition, AllowBots: true, OnMissingField: action,
		IPSelector: func(*gin.Context) string { return peer }, Logger: slog.New(slog.DiscardHandler),
	}})
	server := httptest.NewServer(botEngine(guard, func(c *gin.Context) {
		out := reached{}
		if lookup := vpndetectiongin.FromContext(c); lookup != nil && lookup.Result != nil {
			out.Attached, out.Bogon = true, lookup.Result.IsBogon
			if lookup.Result.UserAgent != nil {
				out.Verdict = string(lookup.Result.UserAgent.Verdict)
			}
		}
		c.JSON(http.StatusOK, out)
	}))
	t.Cleanup(server.Close)

	var replies []reply
	for _, agent := range agents {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		// An empty header is left off the wire, and Go's client would send its
		// own agent were the header absent.
		request.Header.Set("User-Agent", agent)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		raw, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		got := reply{status: response.StatusCode}
		if response.StatusCode == http.StatusOK {
			if err := json.Unmarshal(raw, &got.reached); err != nil {
				t.Fatalf("response body is not one JSON document (%v): %s", err, raw)
			}
		}
		replies = append(replies, got)
	}
	return replies
}

var (
	botCondition    = middleware.Conditions{{"is_bot": true}}
	spoofedVerdict  = middleware.Conditions{{"user_agent": middleware.BlockCondition{"verdict": "spoofed"}}}
	crawlerPeer     = "66.249.66.1"
	fiveCrawlerUAs  = []string{crawlerAgent(1), crawlerAgent(2), crawlerAgent(3), crawlerAgent(4), crawlerAgent(5)}
	fourThenNoAgent = []string{crawlerAgent(1), crawlerAgent(2), crawlerAgent(3), crawlerAgent(4), ""}
)

// One address is looked up with at most four crawler agents an hour: the
// fifth reaches the API bare, and under a condition on is_bot is refused, since
// no verdict vouches for it.
func TestAnAddressIsLookedUpWithAtMostFourCrawlerAgentsEndToEnd(t *testing.T) {
	origin := &crawlerOrigin{}
	replies := askEach(t, origin, crawlerPeer, botCondition, "", fiveCrawlerUAs...)
	for n, got := range replies[:4] {
		if got.status != http.StatusOK || !got.Attached || got.Verdict != "verified" {
			t.Errorf("agent %d answered %+v, want 200 with the verified verdict attached", n+1, got)
		}
	}
	if got := replies[4]; got.status != http.StatusForbidden {
		t.Errorf("the fifth agent answered %d, want the condition's 403", got.status)
	}
	if !slices.Equal(origin.agents, fourThenNoAgent) {
		t.Errorf("the API saw user_agent %q, want the first four agents and then none", origin.agents)
	}
	if !slices.Equal(origin.sent, []bool{true, true, true, true, false}) {
		t.Errorf("the API saw user_agent sent as %v, want four agents and a bare fifth", origin.sent)
	}
}

// Past the bound an address its operator vouches for still passes, and a browser
// on that address is judged by the condition alone.
func TestPastTheBoundAVouchedForCrawlerStillPassesEndToEnd(t *testing.T) {
	origin := &crawlerOrigin{verified: true}
	replies := askEach(t, origin, crawlerPeer, botCondition, "", append(slices.Clone(fiveCrawlerUAs), chrome)...)
	for n, got := range replies[:5] {
		if got.status != http.StatusOK || !got.Attached {
			t.Errorf("agent %d answered %+v, want 200 with the answer attached", n+1, got)
		}
	}
	if want := append(slices.Clone(fourThenNoAgent), ""); !slices.Equal(origin.agents, want) {
		t.Errorf("the API saw user_agent %q, want the first four agents and then none, a browser's included", origin.agents)
	}
	if got := replies[5]; got.status != http.StatusForbidden {
		t.Errorf("a browser on that address answered %d, want the condition's 403", got.status)
	}
}

// An agent that names no crawler is never sent, from an address with room.
func TestABrowsersAgentIsNeverSentEndToEnd(t *testing.T) {
	origin := &crawlerOrigin{}
	replies := askEach(t, origin, crawlerPeer, botCondition, "", chrome)
	if got := replies[0]; got.status != http.StatusForbidden {
		t.Errorf("a browser on a bot's address answered %d, want the condition's 403", got.status)
	}
	if !slices.Equal(origin.sent, []bool{false}) {
		t.Errorf("a browser reached the API as %q, want no agent", origin.agents)
	}
}

// A request that sent no agent has no verdict to lack: under OnMissingField
// error it is answered, not a 500.
func TestARequestWithNoUserAgentReportsNoVerdictGapEndToEnd(t *testing.T) {
	origin := &crawlerOrigin{}
	for _, got := range askEach(t, origin, crawlerPeer, spoofedVerdict, middleware.MissingFieldError, "", chrome) {
		if got.status != http.StatusOK || !got.Attached {
			t.Errorf("answered %+v, want 200 with the answer attached, and no plan gap", got)
		}
	}
	if !slices.Equal(origin.sent, []bool{false, false}) {
		t.Errorf("the API saw user_agent sent as %v, want none", origin.sent)
	}
}

// A bogon peer, local development behind no proxy, is answered locally with no
// verdict, and that is no plan gap: it was answered 500 under OnMissingField
// error.
func TestABogonPeerWithACrawlerAgentIsNoPlanGapEndToEnd(t *testing.T) {
	for _, peer := range []string{"127.0.0.1", "10.0.0.1", "::1"} {
		origin := &crawlerOrigin{}
		got := askEach(t, origin, peer, spoofedVerdict, middleware.MissingFieldError, googlebot)[0]
		if got.status != http.StatusOK || !got.Attached || !got.Bogon {
			t.Errorf("%s: answered %+v, want 200 with a bogon answer attached", peer, got)
		}
		if len(origin.agents) != 0 {
			t.Errorf("%s: a bogon reached the API: %q", peer, origin.agents)
		}
	}
}
