// The middleware half of the shared conformance corpus, asserted END TO END
// through the adapter rather than against the core.
//
// The core's own assertions live in sdk-go's middleware package, once for the
// language. What this adds is that the adapter actually carries the condition
// through, refuses with the status it claims, and reports a plan gap where an
// app can see it - none of which a core-level test can reach.

package vpndetectiongin_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	vpndetectiongin "github.com/vpndetection-io/sdk-go-gin/v2"
	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

// A slog handler that keeps the messages, which is how a warning gets asserted
// on: the middleware's only warning channel is a *slog.Logger.
type recorder struct {
	mu       sync.Mutex
	messages []string
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, record slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, record.Message)
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *recorder) WithGroup(string) slog.Handler { return r }

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.messages)
}

type corpusData struct {
	Middleware struct {
		Conditions []struct {
			Name      string          `json:"name"`
			Why       string          `json:"why"`
			Bogon     string          `json:"bogon"`
			Body      json.RawMessage `json:"body"`
			Condition json.RawMessage `json:"condition"`
			Expect    struct {
				Blocked bool     `json:"blocked"`
				Missing []string `json:"missing"`
			} `json:"expect"`
		} `json:"conditions"`
		InvalidConditions []struct {
			Name      string          `json:"name"`
			Why       string          `json:"why"`
			Condition json.RawMessage `json:"condition"`
		} `json:"invalidConditions"`
	} `json:"middleware"`
}

func TestCorpusConditions(t *testing.T) {
	for _, c := range corpus(t).Middleware.Conditions {
		t.Run(c.Name, func(t *testing.T) {
			ip := c.Bogon
			body := ""
			if ip == "" {
				var served map[string]json.RawMessage
				if err := json.Unmarshal(c.Body, &served); err != nil {
					t.Fatalf("parsing the fixture body: %v", err)
				}
				if err := json.Unmarshal(served["ip"], &ip); err != nil {
					t.Fatalf("parsing the fixture address: %v", err)
				}
				delete(served, "ip")
				rest, err := json.Marshal(served)
				if err != nil {
					t.Fatalf("re-marshalling the fixture body: %v", err)
				}
				// fakeAPI writes `{"ip":<ip>,<body>}`, so the body it takes is
				// the object's members without the braces.
				body = strings.TrimSuffix(strings.TrimPrefix(string(rest), "{"), "}")
			}

			api := newAPI(t, body)
			warnings := &recorder{}
			call := serve(t, vpndetectiongin.Options{
				Options: middleware.Options[*gin.Context]{
					Client:         api.client(t),
					IPSelector:     func(*gin.Context) string { return ip },
					BlockCondition: toConditions(t, c.Condition),
					Logger:         slog.New(warnings),
				},
			})

			status, _ := call(nil)
			want := http.StatusOK
			if c.Expect.Blocked {
				want = http.StatusForbidden
			}
			if status != want {
				t.Errorf("status = %d, want %d (%s)", status, want, c.Why)
			}

			var reported []string
			for _, w := range warnings.seen() {
				if strings.Contains(w, "does not include") {
					reported = append(reported, w)
				}
			}
			if len(reported) != min(len(c.Expect.Missing), 1) {
				t.Fatalf("reported %d plan gaps, want %d (%s)",
					len(reported), min(len(c.Expect.Missing), 1), c.Why)
			}
			for _, member := range c.Expect.Missing {
				if !strings.Contains(reported[0], member) {
					t.Errorf("the warning does not name %q: %s (%s)", member, reported[0], c.Why)
				}
			}
		})
	}
}

func TestCorpusRefusesAConditionThatConstrainsNothing(t *testing.T) {
	for _, c := range corpus(t).Middleware.InvalidConditions {
		t.Run(c.Name, func(t *testing.T) {
			_, err := vpndetectiongin.New(vpndetectiongin.Options{
				Options: middleware.Options[*gin.Context]{
					BlockCondition: toConditions(t, c.Condition),
				},
			})
			if err == nil {
				t.Errorf("New accepted a condition that constrains nothing (%s)", c.Why)
			}
		})
	}
}

// The corpus is language-neutral JSON, so a bound arrives as an object with
// gte/gt/lte/lt keys and an any-of as an array. Rebuilding them into the Go
// types here is what keeps the corpus readable by twelve languages instead of
// carrying one language's spelling.
func toConditions(t *testing.T, raw json.RawMessage) middleware.Conditions {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("parsing the condition: %v", err)
	}
	if list, ok := value.([]any); ok {
		out := make(middleware.Conditions, 0, len(list))
		for _, entry := range list {
			out = append(out, toCondition(t, entry))
		}
		return out
	}
	return middleware.Conditions{toCondition(t, value)}
}

func toCondition(t *testing.T, value any) middleware.BlockCondition {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("a condition must be an object, got %T", value)
	}
	out := middleware.BlockCondition{}
	for key, entry := range object {
		out[key] = toValue(t, entry)
	}
	return out
}

var boundKeys = []string{"gte", "gt", "lte", "lt"}

func toValue(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case []any:
		return middleware.AnyOf(v...)
	case map[string]any:
		if isBound(v) {
			bound := middleware.Bound{}
			for key, n := range v {
				switch key {
				case "gte":
					bound = bound.Gte(n.(float64))
				case "gt":
					bound = bound.Gt(n.(float64))
				case "lte":
					bound = bound.Lte(n.(float64))
				case "lt":
					bound = bound.Lt(n.(float64))
				}
			}
			return bound
		}
		return toCondition(t, v)
	default:
		return value
	}
}

func isBound(object map[string]any) bool {
	if len(object) == 0 {
		return false
	}
	for key := range object {
		if !slices.Contains(boundKeys, key) {
			return false
		}
	}
	return true
}

func corpus(t *testing.T) corpusData {
	t.Helper()
	raw, err := os.ReadFile("testdata/testdata.json")
	if err != nil {
		t.Fatalf("reading the corpus: %v", err)
	}
	var data corpusData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parsing the corpus: %v", err)
	}
	if len(data.Middleware.Conditions) == 0 {
		t.Fatal("no middleware corpus - run emit.mjs in sdk/common")
	}
	return data
}
