package kube

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

type ExecResult struct {
	Stdout string
	Stderr string
}

const (
	DebugPodLabelKey   = "app.kubernetes.io/managed-by"
	DebugPodLabelValue = "kubenetmods"
	DebugPodRoleKey    = "kubenetmods.dev/debug-pod"
	DebugPodRoleValue  = "true"
)

func IsKubeNetModsDebugPod(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	return pod.Labels[DebugPodLabelKey] == DebugPodLabelValue &&
		pod.Labels[DebugPodRoleKey] == DebugPodRoleValue
}

func (c *Client) Exec(ctx context.Context, namespace, pod, container string, command []string) (ExecResult, error) {
	req := c.Core.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.Config, "POST", req.URL())
	if err != nil {
		return ExecResult{}, err
	}
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

func (c *Client) EnsureDebugPod(ctx context.Context, namespace, name, image, imagePullPolicy string, timeout time.Duration) (*corev1.Pod, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("debug pod name cannot be empty")
	}
	existing, err := c.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		if !IsKubeNetModsDebugPod(existing) {
			return nil, fmt.Errorf("refusing to replace pod %s/%s because it is not labeled as a KubeNetMods debug pod", namespace, name)
		}
		if err := c.Core.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	switch imagePullPolicy {
	case "Always":
		pullPolicy = corev1.PullAlways
	case "Never":
		pullPolicy = corev1.PullNever
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				DebugPodLabelKey: DebugPodLabelValue,
				DebugPodRoleKey:  DebugPodRoleValue,
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            "debug",
				Image:           image,
				ImagePullPolicy: pullPolicy,
				Command:         []string{"sleep", "3600"},
			}},
		},
	}
	created, err := c.Core.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var readyPod *corev1.Pod
	err = wait.PollUntilContextCancel(waitCtx, 1*time.Second, true, func(pollCtx context.Context) (bool, error) {
		current, err := c.Core.CoreV1().Pods(namespace).Get(pollCtx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if current.Status.Phase == corev1.PodFailed || current.Status.Phase == corev1.PodSucceeded {
			return false, fmt.Errorf("debug pod ended with phase %s", current.Status.Phase)
		}
		for _, condition := range current.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				readyPod = current
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return created, err
	}
	return readyPod, nil
}

func (c *Client) DeletePodIfExists(ctx context.Context, namespace, name string) error {
	pod, err := c.Core.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !IsKubeNetModsDebugPod(pod) {
		return nil
	}
	err = c.Core.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
