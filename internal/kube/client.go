package kube

import (
	"os"

	istioclient "istio.io/client-go/pkg/clientset/versioned"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Client struct {
	Context   string
	Config    *rest.Config
	Core      kubernetes.Interface
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	Istio     istioclient.Interface
}

func New(contextName string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	} else if home := homedir.HomeDir(); home != "" {
		rules.ExplicitPath = clientcmd.RecommendedHomeFile
	}

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	config, err := loader.ClientConfig()
	if err != nil {
		return nil, err
	}

	core, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	istio, err := istioclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	raw, _ := loader.RawConfig()
	actualContext := raw.CurrentContext
	if contextName != "" {
		actualContext = contextName
	}

	return &Client{
		Context:   actualContext,
		Config:    config,
		Core:      core,
		Dynamic:   dyn,
		Discovery: core.Discovery(),
		Istio:     istio,
	}, nil
}
