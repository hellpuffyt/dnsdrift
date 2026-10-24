package resolver_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hellpuffyt/dnsdrift/internal/resolver"
)

// TestLivePublicResolvers queries the built-in public panel over the real
// network. It is skipped unless DNSDRIFT_LIVE=1, so `go test ./...` never
// depends on public DNS. When enabled, any resolver failing to answer is a
// test failure, not a skip.
//
//	DNSDRIFT_LIVE=1 go test -run TestLivePublicResolvers -v ./internal/resolver/
func TestLivePublicResolvers(t *testing.T) {
	if os.Getenv("DNSDRIFT_LIVE") != "1" {
		t.Skip("live network test; set DNSDRIFT_LIVE=1 to run it")
	}
	for _, wk := range resolver.WellKnown {
		r := resolver.NewDNSResolver(wk.Name, wk.Addr, 5*time.Second)
		ans, err := r.Query(context.Background(), "example.com", resolver.TypeSOA)
		if err != nil || ans.Err != "" || ans.SOA == nil || ans.SOA.Zone != "example.com" {
			t.Errorf("%s (%s): err=%v answer=%+v", wk.Name, wk.Addr, err, ans)
		}
	}
}
