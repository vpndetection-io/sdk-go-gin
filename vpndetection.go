// Package vpndetectiongin is the official Gin middleware for the VPNDetection
// API.
//
// It classifies the visitor behind each request and puts the answer on the
// context, where your handlers can read it. Blocking is opt-in.
package vpndetectiongin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	vpndetection "github.com/vpndetection-io/sdk-go/v4"
	"github.com/vpndetection-io/sdk-go/v4/middleware"
)

// ContextKey is where the answer is stored on the gin.Context, for code that
// would rather read it with c.Get than through FromContext.
const ContextKey = "vpndetection"

// Options configure the middleware. Everything is optional except that you
// almost certainly want an APIKey: the free allowance is counted per source
// address, and a server is one source address.
type Options struct {
	middleware.Options[*gin.Context]

	// OnBlocked answers a blocked request. Defaults to 403 with a short JSON
	// body. Whatever you pass must end the request - Gin will not do it for
	// you, so abort rather than merely writing.
	OnBlocked func(c *gin.Context, lookup *middleware.Lookup)

	// OnError answers a request the middleware could not evaluate at all,
	// which means a misconfiguration rather than a failed lookup - a condition
	// naming a member your plan does not serve, with OnMissingField set to
	// error. Defaults to 500. A failed LOOKUP never reaches this: it lets the
	// request through with the reason on the context.
	OnError func(c *gin.Context, err error)
}

// New builds the middleware, or refuses a condition that could never be what
// anyone meant.
func New(options Options) (gin.HandlerFunc, error) {
	core, err := middleware.New(options.Options, DefaultIPSelector)
	if err != nil {
		return nil, err
	}
	onBlocked := options.OnBlocked
	if onBlocked == nil {
		onBlocked = refuse
	}
	onError := options.OnError
	if onError == nil {
		onError = fail
	}

	return func(c *gin.Context) {
		lookup, err := core.Evaluate(c.Request.Context(), c)
		if err != nil {
			onError(c, err)
			return
		}
		if lookup == nil {
			c.Next()
			return
		}
		c.Set(ContextKey, lookup)
		if lookup.Blocked {
			onBlocked(c, lookup)
			return
		}
		c.Next()
	}, nil
}

// Must is New for a package-level variable or an init, panicking on the
// misconfiguration New would have returned.
func Must(options Options) gin.HandlerFunc {
	handler, err := New(options)
	if err != nil {
		panic(err)
	}
	return handler
}

// FromContext returns what the middleware found out about this visitor, or nil
// when it has not run for this route or Skip claimed the request.
func FromContext(c *gin.Context) *middleware.Lookup {
	value, ok := c.Get(ContextKey)
	if !ok {
		return nil
	}
	lookup, _ := value.(*middleware.Lookup)
	return lookup
}

var selectors = middleware.BindSelectors(func(c *gin.Context) middleware.RequestView {
	return middleware.RequestView{
		Header:      c.GetHeader,
		FrameworkIP: c.ClientIP,
	}
})

// DefaultIPSelector is gin's own c.ClientIP.
//
// Gin DOES walk X-Forwarded-For, but only for peers it trusts, and its default
// TrustedProxies is ALL addresses - so out of the box c.ClientIP returns the
// left-most forwarded entry, which is whatever the caller sent. Set
// engine.SetTrustedProxies to the proxies actually in front of you, or pick
// another selector.
var DefaultIPSelector = selectors.Default

// XFFIPSelector reads X-Forwarded-For directly, ignoring gin's trusted-proxy
// configuration.
//
// The LEFT-MOST entry (depth 0) is whatever the caller sent, because proxies
// append to this header. It is only trustworthy when an edge you control
// overwrites the header. When you know how many proxies sit in front, count
// from the right: depth 1 is the address your nearest proxy saw.
var XFFIPSelector = selectors.XFF

// HeaderIPSelector reads a single-value header your edge writes -
// HeaderIPSelector("CF-Connecting-IP") behind Cloudflare. Falls back to
// c.ClientIP when the header is absent.
var HeaderIPSelector = selectors.Header

// AbortWithStatusJSON, not JSON: Gin runs the rest of the chain unless the
// context is aborted, so a refusal that only writes would be followed by the
// handler answering the same request.
func refuse(c *gin.Context, _ *middleware.Lookup) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied"})
}

func fail(c *gin.Context, _ error) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
}

// Re-exported so a caller writing a condition or reading a result never has to
// import two packages.
type (
	BlockCondition = middleware.BlockCondition
	Conditions     = middleware.Conditions
	Bound          = middleware.Bound
	Lookup         = middleware.Lookup
	Result         = vpndetection.Result
)

// Gte bounds a numeric member at or above v. Gte(5).Lt(100) is a range.
func Gte(v float64) Bound { return middleware.Gte(v) }

// Gt bounds a numeric member strictly above v.
func Gt(v float64) Bound { return middleware.Gt(v) }

// Lte bounds a numeric member at or below v.
func Lte(v float64) Bound { return middleware.Lte(v) }

// Lt bounds a numeric member strictly below v.
func Lt(v float64) Bound { return middleware.Lt(v) }

// AnyOf matches a member equal to any one of these.
func AnyOf(values ...any) any { return middleware.AnyOf(values...) }
