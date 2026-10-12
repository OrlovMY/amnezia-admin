package core_test

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestEndpointIPv6Brackets — IPv6 в Endpoint — в квадратных скобках.
func TestEndpointIPv6Brackets(t *testing.T) {
	sess := core.NewSessionWithRunner(fakesrv.New(), &core.ServerCreds{Host: "2001:db8::1", User: "root"})
	nu, err := sess.AddUser(raceContainer(), "Carol")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nu.Config, "Endpoint = [2001:db8::1]:") {
		t.Errorf("%s", nu.Config)
	}
}
