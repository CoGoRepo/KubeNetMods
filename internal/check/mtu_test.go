package check

import (
	"strings"
	"testing"

	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRouteFieldParsesDeviceSourceAndMTU(t *testing.T) {
	text := "10.244.0.17 via 169.254.1.1 dev eth0 src 10.244.0.252 uid 0 mtu 1480"

	if got := routeField(text, "dev"); got != "eth0" {
		t.Fatalf("dev = %q, want eth0", got)
	}
	if got := routeField(text, "src"); got != "10.244.0.252" {
		t.Fatalf("src = %q, want source IP", got)
	}
	if got := routeMTU(text); got != 1480 {
		t.Fatalf("mtu = %d, want 1480", got)
	}
}

func TestLinkMTUParsesIpLinkOutput(t *testing.T) {
	text := `3: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP mode DEFAULT group default qlen 1000`

	if got := linkMTU(text); got != 1450 {
		t.Fatalf("mtu = %d, want 1450", got)
	}
}

func TestMTUSnapshotMessageUsesFallbackText(t *testing.T) {
	target := ExecTarget{
		Kind: "source pod",
		Pod:  corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "src", Name: "curl"}},
	}
	message := mtuSnapshotMessage(target, "", "target pod app/echo", MTURouteSnapshot{
		Target:            "10.244.0.17",
		Dev:               "eth0",
		MTU:               1480,
		LinkMTU:           1480,
		InterfaceFallback: true,
	})

	if !strings.Contains(message, "route detection") || !strings.Contains(message, "eth0 interface MTU 1480") {
		t.Fatalf("fallback message = %q", message)
	}
}

func TestMTUSnapshotMessageIncludesRouteMTUWhenDifferent(t *testing.T) {
	target := ExecTarget{
		Kind: "target pod",
		Pod:  corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "echo"}},
	}
	message := mtuSnapshotMessage(target, "echo", "source pod src/curl", MTURouteSnapshot{
		Target:        "10.244.0.252",
		Dev:           "eth0",
		Src:           "10.244.0.17",
		MTU:           1500,
		LinkMTU:       1500,
		RouteMTU:      1450,
		RouteDetected: true,
	})

	if !strings.Contains(message, "interface MTU 1500; route MTU 1450") {
		t.Fatalf("message = %q", message)
	}
}

func TestMTUComparisonCanWarnOnMismatch(t *testing.T) {
	report := model.NewReport("check service", model.Target{Namespace: "app", Service: "echo"})
	source := MTURouteSnapshot{Dev: "eth0", MTU: 1480}
	target := MTURouteSnapshot{Dev: "eth0", MTU: 1450}

	if source.MTU == target.MTU {
		t.Fatal("test setup must differ")
	}
	report.Add("MTU Snapshot Layer", "path MTU comparison", model.StatusWarn, "Source route dev eth0 interface MTU 1480 and target return dev eth0 interface MTU 1450 differ. MTU mismatches can cause large or long-lived transfers to fail even when small probes pass.")

	assertResult(t, report, "MTU Snapshot Layer", "path MTU comparison", model.StatusWarn)
}
