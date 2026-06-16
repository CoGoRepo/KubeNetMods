package kube

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestEnsureDebugPodRefusesToReplaceUnownedPod(t *testing.T) {
	ctx := context.Background()
	client := &Client{Core: k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "app"},
	})}

	_, err := client.EnsureDebugPod(ctx, "app", "api", "nicolaka/netshoot:latest", "IfNotPresent", time.Nanosecond)
	if err == nil || !strings.Contains(err.Error(), "refusing to replace pod app/api") {
		t.Fatalf("expected refusal for unowned pod, got %v", err)
	}

	if _, err := client.Core.CoreV1().Pods("app").Get(ctx, "api", metav1.GetOptions{}); err != nil {
		t.Fatalf("unowned pod should still exist: %v", err)
	}
	for _, action := range client.Core.(*k8sfake.Clientset).Actions() {
		if action.GetVerb() == "delete" || action.GetVerb() == "create" {
			t.Fatalf("unexpected %s action against unowned pod", action.GetVerb())
		}
	}
}

func TestDeletePodIfExistsLeavesUnownedPod(t *testing.T) {
	ctx := context.Background()
	client := &Client{Core: k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "app"},
	})}

	if err := client.DeletePodIfExists(ctx, "app", "api"); err != nil {
		t.Fatalf("DeletePodIfExists returned error: %v", err)
	}
	if _, err := client.Core.CoreV1().Pods("app").Get(ctx, "api", metav1.GetOptions{}); err != nil {
		t.Fatalf("unowned pod should still exist: %v", err)
	}
}

func TestDeletePodIfExistsDeletesOwnedDebugPod(t *testing.T) {
	ctx := context.Background()
	client := &Client{Core: k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubenetmods-source-debug",
			Namespace: "app",
			Labels: map[string]string{
				DebugPodLabelKey: DebugPodLabelValue,
				DebugPodRoleKey:  DebugPodRoleValue,
			},
		},
	})}

	if err := client.DeletePodIfExists(ctx, "app", "kubenetmods-source-debug"); err != nil {
		t.Fatalf("DeletePodIfExists returned error: %v", err)
	}
	_, err := client.Core.CoreV1().Pods("app").Get(ctx, "kubenetmods-source-debug", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected owned debug pod to be deleted, got %v", err)
	}
}

func TestEnsureDebugPodLabelsCreatedPod(t *testing.T) {
	ctx := context.Background()
	client := &Client{Core: k8sfake.NewSimpleClientset()}

	_, err := client.EnsureDebugPod(ctx, "app", "kubenetmods-source-debug", "nicolaka/netshoot:latest", "IfNotPresent", time.Nanosecond)
	if err == nil {
		t.Fatal("expected timeout waiting for fake pod readiness")
	}

	pod, getErr := client.Core.CoreV1().Pods("app").Get(ctx, "kubenetmods-source-debug", metav1.GetOptions{})
	if getErr != nil {
		t.Fatalf("expected debug pod to be created: %v", getErr)
	}
	if !IsKubeNetModsDebugPod(pod) {
		t.Fatalf("created pod is missing KubeNetMods debug labels: %#v", pod.Labels)
	}
}
