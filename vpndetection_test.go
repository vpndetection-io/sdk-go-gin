// The adapter, against a real Gin engine on a real socket, with a real
// httptest.Server standing in for the API.
//
// A test server answers on the loopback, so the socket peer is a bogon and is
// answered locally without a request. Anything that needs a served answer
// therefore has to arrive wearing a public address, through a selector.

package vpndetectiongin_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	vpndetectiongin "github.com/vpndetection-io/sdk-go-gin/v2"
	vpndetection "github.com/vpndetection-io/sdk-go/v5"
	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

func init() { gin.SetMode(gin.TestMode) }

const publicIP = "45.83.91.1"

type answer struct {
	IP       string `json:"ip"`
	IsVpn    bool   `json:"is_vpn"`
	IsBogon  bool   `json:"is_bogon"`
	Err      string `json:"err"`
	Attached bool   `json:"attached"`
}

// A stand-in API that answers every lookup the same way and records the
// addresses it was asked about, which is what the client-address tests assert
// on rather than assume.
type fakeAPI struct {
	mu     sync.Mutex
	asked  []string
	body   string
	status int
	hang   bool
	server *httptest.Server
}

func newAPI(t *testing.T, body string) *fakeAPI {
	t.Helper()
	api := &fakeAPI{body: body}
	api.server = httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.server.Close)
	return api
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if a.hang {
		<-r.Context().Done()
		return
	}
	ip := strings.TrimPrefix(r.URL.Path, "/")
	a.mu.Lock()
	a.asked = append(a.asked, ip)
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if a.status != 0 {
		w.WriteHeader(a.status)
		fmt.Fprint(w, `{"error":"boom"}`)
		return
	}
	body := a.body
	if body == "" {
		body = `"is_vpn":true,"vpn":{"provider":"nordvpn"}`
	}
	fmt.Fprintf(w, `{"ip":%q,%s}`, ip, body)
}

func (a *fakeAPI) addresses() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.asked...)
}

func (a *fakeAPI) client(t *testing.T, extra ...vpndetection.Option) *vpndetection.Client {
	t.Helper()
	options := append([]vpndetection.Option{
		vpndetection.WithBaseURL(a.server.URL),
		vpndetection.WithoutCache(),
		vpndetection.WithRetries(0),
	}, extra...)
	client, err := vpndetection.New(options...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func fixedIP(*gin.Context) string { return publicIP }

// Stands up the middleware in front of a handler that reports what reached it.
//
// TrustedProxies is cleared, because gin's DEFAULT is to trust every peer and
// therefore to believe a forged X-Forwarded-For. A suite built on the default
// would be asserting the forgery is the client.
func serve(t *testing.T, options vpndetectiongin.Options) func(headers map[string]string) (int, answer) {
	t.Helper()
	mw, err := vpndetectiongin.New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	engine := gin.New()
	if err := engine.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	engine.Use(mw)
	engine.GET("/", func(c *gin.Context) {
		lookup := vpndetectiongin.FromContext(c)
		out := answer{Attached: lookup != nil}
		if lookup != nil {
			out.IP = lookup.IP
			if lookup.Result != nil {
				out.IsVpn = lookup.Result.IsVpn
				out.IsBogon = lookup.Result.IsBogon
			}
			if lookup.Err != nil {
				out.Err = lookup.Err.Error()
			}
		}
		c.JSON(http.StatusOK, out)
	})
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	return func(headers map[string]string) (int, answer) {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		var out answer
		// Checked, not swallowed: when a middleware writes a refusal and then
		// lets the handler run anyway, both bodies land and the result is two
		// concatenated JSON documents. Ignoring the error turns that into a
		// zero-valued answer that looks exactly like a correct refusal.
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("response body is not one JSON document (%v): %s", err, raw)
		}
		return response.StatusCode, out
	}
}

func TestEnrichesTheRequestAndLeavesTheDecisionToTheApp(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client: api.client(t), IPSelector: fixedIP,
	}})

	status, out := call(nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !out.Attached || !out.IsVpn || out.IP != publicIP {
		t.Errorf("answer = %+v, want an attached VPN answer for %s", out, publicIP)
	}
	if got := api.addresses(); len(got) != 1 || got[0] != publicIP {
		t.Errorf("asked about %v, want [%s]", got, publicIP)
	}
}

func TestBlocksWhenTheConditionMatches(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	if status, _ := call(nil); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}

	clean := newAPI(t, `"is_vpn":false,"vpn":{}`)
	allowed := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         clean.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	if status, _ := allowed(nil); status != http.StatusOK {
		t.Errorf("status = %d, want 200 for a clean address", status)
	}
}

// The handler must not run for a blocked request. Asserting only the status
// would pass even if it did, because the refusal is written first.
func TestABlockedRequestNeverReachesTheHandler(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	status, out := call(nil)
	if status != http.StatusForbidden || out.Attached {
		t.Errorf("status = %d, attached = %v; the handler answered a blocked request",
			status, out.Attached)
	}
}

func TestAConditionReachesTheEvidenceFields(t *testing.T) {
	nord := newAPI(t, `"is_vpn":true,"vpn":{"provider":"nordvpn"}`)
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:     nord.client(t),
		IPSelector: fixedIP,
		BlockCondition: middleware.Conditions{
			{"vpn": middleware.BlockCondition{"provider": "mullvad"}},
		},
	}})
	if status, _ := call(nil); status != http.StatusOK {
		t.Errorf("status = %d, want 200; a different provider must not match", status)
	}

	mullvad := newAPI(t, `"is_vpn":true,"vpn":{"provider":"MULLVAD"}`)
	call2 := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:     mullvad.client(t),
		IPSelector: fixedIP,
		BlockCondition: middleware.Conditions{
			{"vpn": middleware.BlockCondition{"provider": "mullvad"}},
		},
	}})
	if status, _ := call2(nil); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403; a provider must compare without case", status)
	}
}

func TestOnBlockedReplacesTheRefusal(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{
		Options: middleware.Options[*gin.Context]{
			Client:         api.client(t),
			IPSelector:     fixedIP,
			BlockCondition: middleware.Conditions{{"is_vpn": true}},
		},
		OnBlocked: func(c *gin.Context, lookup *middleware.Lookup) {
			c.AbortWithStatusJSON(http.StatusTeapot,
				gin.H{"why": *lookup.Result.Vpn.Provider})
		},
	})
	status, _ := call(nil)
	if status != http.StatusTeapot {
		t.Errorf("status = %d, want 418", status)
	}
}

func TestSkipLeavesTheRequestUntouched(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
		Skip:           func(c *gin.Context) bool { return c.Request.URL.Path == "/" },
	}})
	status, out := call(nil)
	if status != http.StatusOK || out.Attached {
		t.Errorf("status = %d, attached = %v; skip should claim the request", status, out.Attached)
	}
	if got := api.addresses(); len(got) != 0 {
		t.Errorf("asked about %v, want nothing", got)
	}
}

func TestAFailingLookupLetsTheVisitorThrough(t *testing.T) {
	api := newAPI(t, "")
	api.status = http.StatusInternalServerError
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	status, out := call(nil)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200; our outage must not become the customer's", status)
	}
	if out.Err == "" {
		t.Error("the reason should be on the context")
	}
}

func TestFailClosedBlocksOnAFailedLookup(t *testing.T) {
	api := newAPI(t, "")
	api.status = http.StatusInternalServerError
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
		FailClosed:     true,
	}})
	if status, _ := call(nil); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
}

func TestOnMissingFieldErrorBecomesA500(t *testing.T) {
	free := newAPI(t, `"is_vpn":true`)
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         free.client(t),
		IPSelector:     fixedIP,
		BlockCondition: middleware.Conditions{{"is_hosting": true}},
		OnMissingField: middleware.MissingFieldError,
	}})
	if status, _ := call(nil); status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
}

// The test that matters. Every other assertion here would pass whether or not
// the selector is right, because a direct connection has nothing to confuse.
func TestAForgedXForwardedForIsIgnoredByDefault(t *testing.T) {
	forgery := map[string]string{"X-Forwarded-For": publicIP}

	plain := newAPI(t, "")
	untrusting := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client: plain.client(t),
	}})
	_, direct := untrusting(forgery)
	if direct.IP != "127.0.0.1" {
		t.Errorf("resolved %q, want the socket peer; the header is a forgery", direct.IP)
	}
	if got := plain.addresses(); len(got) != 0 {
		t.Errorf("asked about %v; a bogon is answered locally", got)
	}

	explicit := newAPI(t, "")
	viaSelector := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:     explicit.client(t),
		IPSelector: vpndetectiongin.XFFIPSelector(0),
	}})
	if _, out := viaSelector(forgery); out.IP != publicIP {
		t.Errorf("resolved %q, want %q", out.IP, publicIP)
	}
}

func TestAHeaderSelectorReadsTheEdgeThatWritesIt(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:     api.client(t),
		IPSelector: vpndetectiongin.HeaderIPSelector("CF-Connecting-IP"),
	}})
	if _, out := call(map[string]string{"CF-Connecting-IP": "45.83.91.9"}); out.IP != "45.83.91.9" {
		t.Errorf("resolved %q, want 45.83.91.9", out.IP)
	}
	if _, out := call(nil); out.IP != "127.0.0.1" {
		t.Errorf("resolved %q, want the socket peer when the edge wrote no header", out.IP)
	}
}

func TestDepthCountsTrustedHopsFromTheRight(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:     api.client(t),
		IPSelector: vpndetectiongin.XFFIPSelector(1),
	}})
	call(map[string]string{
		"X-Forwarded-For": publicIP + ", 70.41.3.18, 150.172.238.178",
	})
	if got := api.addresses(); len(got) != 1 || got[0] != "150.172.238.178" {
		t.Errorf("asked about %v, want [150.172.238.178]", got)
	}
}

func TestTheDefaultSelectorIsGinsClientIP(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client: api.client(t), IPSelector: vpndetectiongin.DefaultIPSelector,
	}})
	if _, out := call(nil); out.IP != "127.0.0.1" {
		t.Errorf("resolved %q, want a bare 127.0.0.1", out.IP)
	}
}

// Gin is NOT net/http here, and the difference is the whole reason this test
// exists: gin.ClientIP does walk X-Forwarded-For, and its default TrustedProxies
// is every address, so out of the box it returns whatever the caller sent.
// Measured rather than assumed, because a README that got this backwards would
// send people to the wrong fix.
func TestGinsDefaultTrustsAForgedHeaderUntilYouNarrowTrustedProxies(t *testing.T) {
	forged := func(engine *gin.Engine) string {
		engine.GET("/", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
		server := httptest.NewServer(engine)
		t.Cleanup(server.Close)
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
		request.Header.Set("X-Forwarded-For", publicIP)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return string(raw)
	}

	if got := forged(gin.New()); got != publicIP {
		t.Errorf("a default engine resolved %q, want the forgery %q - if gin has changed "+
			"its default, the README and the selector docs have to change with it", got, publicIP)
	}

	narrowed := gin.New()
	if err := narrowed.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	if got := forged(narrowed); got != "127.0.0.1" {
		t.Errorf("with no trusted proxies gin resolved %q, want the socket peer", got)
	}
}

func TestAPrivateClientAddressIsAnsweredLocallyAndNeverBlocks(t *testing.T) {
	api := newAPI(t, "")
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	status, out := call(nil)
	if status != http.StatusOK {
		t.Errorf("status = %d; local development must not lock you out of your own app", status)
	}
	if !out.IsBogon {
		t.Error("a loopback address should be answered locally")
	}
	if got := api.addresses(); len(got) != 0 {
		t.Errorf("asked about %v, want nothing", got)
	}
}

func TestTheDeadlineBoundsTheRequest(t *testing.T) {
	api := newAPI(t, "")
	api.hang = true
	call := serve(t, vpndetectiongin.Options{Options: middleware.Options[*gin.Context]{
		Client:         api.client(t),
		IPSelector:     fixedIP,
		Timeout:        150 * time.Millisecond,
		BlockCondition: middleware.Conditions{{"is_vpn": true}},
	}})
	started := time.Now()
	status, out := call(nil)
	if status != http.StatusOK || out.Err == "" {
		t.Errorf("status = %d, err = %q; want a fail-open with the reason recorded", status, out.Err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Errorf("the visitor was held %v, past the budget", elapsed)
	}
}

func TestAConditionThatConstrainsNothingIsRefused(t *testing.T) {
	for _, condition := range []middleware.Conditions{
		{{"is_vpn": false}},
		{{}},
	} {
		if _, err := vpndetectiongin.New(vpndetectiongin.Options{
			Options: middleware.Options[*gin.Context]{BlockCondition: condition},
		}); err == nil {
			t.Errorf("New accepted %v, which would block every request", condition)
		}
	}
}

// The README's own setup, an APIKey and nothing else. Through sdk-go v5.5.0 New
// refused it, and Must panicked, because the core passed the unset BaseURL on.
// The README's app as written: its trusted proxies, and the middleware built from
// an API key alone, so the client, the base URL and the transport are the SDK's
// defaults. The default transport answers for the API's host alone, which is
// why this test swaps a global and never runs in parallel.
func TestTheREADMEsAppLooksUpTheVisitorWithOnlyAnAPIKey(t *testing.T) {
	for _, key := range []string{"key", ""} {
		t.Run("key "+map[bool]string{true: "set", false: "unset"}[key != ""], func(t *testing.T) {
			api := &apiHost{}
			saved := http.DefaultTransport
			http.DefaultTransport = api
			t.Cleanup(func() { http.DefaultTransport = saved })

			engine := gin.New()
			if err := engine.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
				t.Fatalf("SetTrustedProxies: %v", err)
			}
			engine.Use(vpndetectiongin.Must(vpndetectiongin.Options{
				Options: middleware.Options[*gin.Context]{APIKey: key},
			}))
			engine.GET("/", func(c *gin.Context) {
				lookup := vpndetectiongin.FromContext(c)
				if lookup.Result != nil && lookup.Result.IsVpn {
					c.String(http.StatusOK, "Hello, VPN user")
					return
				}
				c.String(http.StatusOK, "Hello")
			})

			// A proxy inside 10.0.0.0/8 names the visitor; a peer outside it
			// cannot, so its forged header names nobody.
			for peer, want := range map[string]string{"10.1.2.3:4567": publicIP, "45.83.91.9:4567": "45.83.91.9"} {
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.RemoteAddr = peer
				request.Header.Set("X-Forwarded-For", publicIP)
				recorder := httptest.NewRecorder()
				engine.ServeHTTP(recorder, request)
				if body := recorder.Body.String(); body != "Hello, VPN user" {
					t.Errorf("from %s answered %q, want the VPN visitor's page", peer, body)
				}
				if got := api.last(); got.path != "/"+want || got.auth != map[bool]string{true: "Bearer key"}[key != ""] {
					t.Errorf("from %s asked %+v, want /%s with the key only when one is set", peer, got, want)
				}
			}
		})
	}
}

// The API's host, answering every lookup as a VPN visitor and recording what it
// was asked. Any other host is refused, so nothing leaves the test.
type apiHost struct {
	mu   sync.Mutex
	sent []apiRequest
}

type apiRequest struct{ path, auth string }

func (a *apiHost) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "api.vpndetection.io" {
		return nil, fmt.Errorf("unexpected host %q", request.URL.Host)
	}
	a.mu.Lock()
	a.sent = append(a.sent, apiRequest{path: request.URL.Path, auth: request.Header.Get("Authorization")})
	a.mu.Unlock()
	ip := strings.TrimPrefix(request.URL.Path, "/")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"ip":%q,"is_vpn":true}`, ip))),
		Request:    request,
	}, nil
}

func (a *apiHost) last() apiRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sent) == 0 {
		return apiRequest{}
	}
	return a.sent[len(a.sent)-1]
}
