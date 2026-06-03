package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/CoGoRepo/KubeNetMods/internal/kube"
	"github.com/CoGoRepo/KubeNetMods/internal/model"
	corev1 "k8s.io/api/core/v1"
)

func checkMTUPath(ctx context.Context, client *kube.Client, report *model.Report, service *corev1.Service, targetPods []corev1.Pod, source *ExecTarget) {
	layer := "MTU Snapshot Layer"
	if source == nil {
		report.Add(layer, "source route MTU", model.StatusSkip, "Skipped because no executable source pod/debug pod was available.")
		return
	}
	if service == nil {
		report.Add(layer, "source route MTU", model.StatusSkip, "Skipped because the target Service was not readable.")
		return
	}

	var sourceToPod *MTURouteSnapshot
	if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone {
		if snapshot, container, err := readMTURouteSnapshotAnyContainer(ctx, *source, service.Spec.ClusterIP); err != nil {
			report.Add(layer, "source route to Service ClusterIP", model.StatusSkip, fmt.Sprintf("Could not read route-selected MTU from %s %q: %s", source.Kind, source.Pod.Name, mtuSnapshotErrorText(err)))
		} else {
			report.Add(layer, "source route to Service ClusterIP", model.StatusInfo, mtuSnapshotMessage(*source, container, "Service ClusterIP", snapshot))
		}
	}

	target := selectReadyPod(targetPods)
	if target == nil || target.Status.PodIP == "" {
		return
	}
	snapshot, sourceContainer, err := readMTURouteSnapshotAnyContainer(ctx, *source, target.Status.PodIP)
	if err != nil {
		report.Add(layer, "source route to target pod", model.StatusSkip, fmt.Sprintf("Could not read route-selected MTU from %s %q: %s", source.Kind, source.Pod.Name, mtuSnapshotErrorText(err)))
	} else {
		sourceToPod = &snapshot
		report.Add(layer, "source route to target pod", model.StatusInfo, mtuSnapshotMessage(*source, sourceContainer, "target pod "+target.Namespace+"/"+target.Name, snapshot))
	}

	if source.Pod.Status.PodIP == "" {
		return
	}
	targetExec := ExecTarget{Client: client, Pod: *target, Kind: "target pod"}
	returnSnapshot, targetContainer, err := readMTURouteSnapshotAnyContainer(ctx, targetExec, source.Pod.Status.PodIP)
	if err != nil {
		return
	}
	report.Add(layer, "target return route", model.StatusInfo, mtuSnapshotMessage(targetExec, targetContainer, "source pod "+source.Pod.Namespace+"/"+source.Pod.Name, returnSnapshot))

	if sourceToPod == nil || sourceToPod.MTU == 0 || returnSnapshot.MTU == 0 {
		return
	}
	if sourceToPod.MTU == returnSnapshot.MTU {
		report.Add(layer, "path MTU comparison", model.StatusPass, fmt.Sprintf("Source route dev %s interface MTU %d and target return dev %s interface MTU %d match.", sourceToPod.Dev, sourceToPod.MTU, returnSnapshot.Dev, returnSnapshot.MTU))
		return
	}
	report.Add(layer, "path MTU comparison", model.StatusWarn, fmt.Sprintf("Source route dev %s interface MTU %d and target return dev %s interface MTU %d differ. MTU mismatches can cause large or long-lived transfers to fail even when small probes pass.", sourceToPod.Dev, sourceToPod.MTU, returnSnapshot.Dev, returnSnapshot.MTU))
}

func readMTURouteSnapshotAnyContainer(ctx context.Context, target ExecTarget, targetIP string) (MTURouteSnapshot, string, error) {
	var attempts []string
	add := func(container string) {
		for _, existing := range attempts {
			if existing == container {
				return
			}
		}
		attempts = append(attempts, container)
	}
	add(target.Container)
	for _, container := range target.Pod.Spec.Containers {
		add(container.Name)
	}
	var lastErr error
	for _, container := range attempts {
		current := target
		current.Container = container
		snapshot, err := readMTURouteSnapshot(ctx, current, targetIP)
		if err == nil {
			return snapshot, container, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("pod has no containers to exec")
	}
	return MTURouteSnapshot{}, "", lastErr
}

func mtuSnapshotMessage(target ExecTarget, container string, label string, snapshot MTURouteSnapshot) string {
	mtu := "unknown"
	if snapshot.MTU > 0 {
		mtu = fmt.Sprintf("%d", snapshot.MTU)
	}
	mtuText := "interface MTU " + mtu
	if snapshot.RouteMTU > 0 && snapshot.RouteMTU != snapshot.MTU {
		mtuText += fmt.Sprintf("; route MTU %d", snapshot.RouteMTU)
	}
	src := ""
	if snapshot.Src != "" {
		src = " src " + snapshot.Src
	}
	containerText := ""
	if container != "" && container != target.Container {
		containerText = fmt.Sprintf(" using container %q", container)
	}
	if snapshot.RouteDetected {
		return fmt.Sprintf("%s %q%s route to %s %s uses dev %s%s %s.", target.Kind, target.Pod.Name, containerText, label, snapshot.Target, snapshot.Dev, src, mtuText)
	}
	if snapshot.InterfaceFallback {
		return fmt.Sprintf("%s %q%s route detection for %s %s did not identify a device; eth0 %s.", target.Kind, target.Pod.Name, containerText, label, snapshot.Target, mtuText)
	}
	return fmt.Sprintf("%s %q%s MTU for route to %s %s uses dev %s%s %s.", target.Kind, target.Pod.Name, containerText, label, snapshot.Target, snapshot.Dev, src, mtuText)
}

func mtuSnapshotErrorText(err error) string {
	if err == nil {
		return "(unknown error)"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "executable file not found") && strings.Contains(text, `"sh"`):
		return "sh was not available in a usable container; MTU snapshot skipped."
	case strings.Contains(text, "executable file not found") && strings.Contains(text, `"ip"`):
		return "ip command was not available in a usable container; MTU snapshot skipped."
	case strings.Contains(text, "not found") && strings.Contains(text, "ip"):
		return "ip command was not available in a usable container; MTU snapshot skipped."
	default:
		return compactCommandOutput(err.Error())
	}
}
