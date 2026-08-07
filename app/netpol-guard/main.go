// netpol-guard — phase 8.
//
// Enforces one invariant in one namespace: EVERY POD MUST BE ISOLATED BY A
// NETWORKPOLICY IN BOTH DIRECTIONS (Ingress and Egress).
//
// Why this cannot be an admission policy. Admission validates the object being
// written. The violation this controller catches is caused by DELETING AN
// UNRELATED OBJECT: remove the namespace-wide `default-deny` NetworkPolicy and
// a pod that was never touched — no create, no update, no admission request of
// any kind for that pod — silently loses its protection. There is no request
// at the moment the protection disappears, so there is nothing for a
// ValidatingPolicy or a PSA profile to evaluate. Only something that
// continuously reconciles observed cluster state can notice. That is the
// entire justification for writing a controller instead of another policy.
//
// Two modes, one flag apart:
//
//	--remediate=false (default)  detect only: report and do nothing.
//	--remediate=true             restore the baseline `default-deny` policy.
//
// The controller NEVER updates and NEVER deletes a NetworkPolicy. Its only
// write is a single Create of `default-deny` when that object is absent, and
// its RBAC (docs/evidence/phase-8-netpol-guard/rbac.yaml) grants no update,
// patch or delete verb — so "it will not touch a policy it did not create" is
// enforced by the apiserver, not just by this code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// baselinePolicyName is the object remediation restores. It is the
	// namespace-wide deny that gives every pod isolation in both directions.
	baselinePolicyName = "default-deny"

	// fieldManager tags the Create so the live object's managedFields record
	// which writer produced it — this controller, or kubectl.
	fieldManager = "netpol-guard"

	// tsLayout is RFC3339 with milliseconds: the exposure window between a
	// policy being deleted and remediation landing is measured in fractions
	// of a scan interval, so seconds are not enough resolution.
	tsLayout = "2006-01-02T15:04:05.000Z07:00"
)

// exit codes: 0 clean, 1 invariant violated (--once, detect-only), 2 error.
const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
)

func logf(format string, args ...any) {
	fmt.Printf("%s %s\n", time.Now().Format(tsLayout), fmt.Sprintf(format, args...))
}

func main() {
	var (
		namespace  = flag.String("namespace", "demo", "namespace whose pods must all be NetworkPolicy-isolated")
		remediate  = flag.Bool("remediate", false, "restore the baseline default-deny NetworkPolicy when the invariant is violated; detect-only when false")
		interval   = flag.Duration("interval", 30*time.Second, "time between scans")
		kubeconfig = flag.String("kubeconfig", "", "path to a kubeconfig; when empty, in-cluster config is used")
		once       = flag.Bool("once", false, "run a single scan and exit; exits 1 on a violation in detect-only mode")
	)
	flag.Parse()

	os.Exit(run(*namespace, *remediate, *interval, *kubeconfig, *once))
}

func run(namespace string, remediate bool, interval time.Duration, kubeconfig string, once bool) int {
	source := "in-cluster serviceaccount"
	if kubeconfig != "" {
		source = "kubeconfig " + kubeconfig
	}

	config, err := buildConfig(kubeconfig)
	if err != nil {
		logf("FATAL could not build client config from %s: %v", source, err)
		return exitError
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logf("FATAL could not build clientset: %v", err)
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logf("netpol-guard start namespace=%s remediate=%t interval=%s once=%t auth=%s apiserver=%s",
		namespace, remediate, interval, once, source, config.Host)
	logf("invariant: every pod in namespace %s must be selected by a NetworkPolicy for BOTH Ingress and Egress", namespace)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	worst := exitOK
	for scanNum := 1; ; scanNum++ {
		violations, err := scan(ctx, client, namespace, scanNum)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			logf("ERROR scan=%d failed: %v", scanNum, err)
			worst = exitError
		}

		if len(violations) > 0 {
			if remediate {
				if err := restoreBaseline(ctx, client, namespace); err != nil {
					logf("ERROR scan=%d remediation failed: %v", scanNum, err)
					worst = exitError
				}
			} else if worst == exitOK {
				worst = exitViolation
			}
		}

		if once {
			break
		}

		select {
		case <-ctx.Done():
			logf("netpol-guard stopping after signal")
			return worst
		case <-ticker.C:
		}
	}

	if !once {
		return worst
	}
	// --once is the evidence/CI mode: a detect-only run that saw a violation
	// exits non-zero so a pipeline fails. In --remediate mode the violation
	// was acted on, so only a real error is worth a non-zero exit.
	if remediate && worst == exitViolation {
		return exitOK
	}
	return worst
}

// buildConfig honours the flag contract exactly: empty kubeconfig means
// in-cluster. There is no silent fallback to ~/.kube/config, because a
// controller that quietly picks up an operator's admin credentials when its
// ServiceAccount token is missing is a security bug, not a convenience.
func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// scan lists the namespace, evaluates the invariant, and logs one verdict line
// plus one line per violation. It returns the violating pods.
func scan(ctx context.Context, client kubernetes.Interface, namespace string, scanNum int) ([]PodIsolation, error) {
	podList, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}
	policyList, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing networkpolicies: %w", err)
	}

	// Terminal-phase pods have no running container and no network to protect,
	// so counting them would produce permanent false violations in any
	// namespace that has ever run a Job. Everything else is in scope.
	live := make([]corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		live = append(live, pod)
	}

	verdicts, err := Evaluate(live, policyList.Items)
	if err != nil {
		return nil, err
	}

	var violations []PodIsolation
	for _, verdict := range verdicts {
		if verdict.Violated() {
			violations = append(violations, verdict)
			logf("VIOLATION scan=%d pod=%s missing=%s isolated-for-ingress-by=%s isolated-for-egress-by=%s",
				scanNum, verdict.Name, strings.Join(verdict.Missing(), ","),
				fmtList(verdict.IngressBy), fmtList(verdict.EgressBy))
		}
	}

	outcome := "HOLDS"
	if len(violations) > 0 {
		outcome = "VIOLATED"
	}
	logf("scan=%d namespace=%s pods=%d networkpolicies=%d violations=%d verdict=%s",
		scanNum, namespace, len(live), len(policyList.Items), len(violations), outcome)

	return violations, nil
}

// restoreBaseline creates `default-deny` if and only if it is absent. It is
// idempotent, it never updates and never deletes, and it says so out loud when
// the baseline already exists — because in that case the violation has some
// other cause and this controller cannot fix it.
func restoreBaseline(ctx context.Context, client kubernetes.Interface, namespace string) error {
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, baselinePolicyName, metav1.GetOptions{})
	switch {
	case err == nil:
		logf("REMEDIATE baseline networkpolicy/%s already present in %s — no action; this controller never modifies or deletes an existing policy, so a violation that survives this line has a cause outside its scope",
			baselinePolicyName, namespace)
		return nil
	case !apierrors.IsNotFound(err):
		return fmt.Errorf("checking for networkpolicy/%s: %w", baselinePolicyName, err)
	}

	logf("REMEDIATE baseline networkpolicy/%s is ABSENT in %s — creating it", baselinePolicyName, namespace)
	created, err := client.NetworkingV1().NetworkPolicies(namespace).Create(
		ctx, baselineDefaultDeny(namespace), metav1.CreateOptions{FieldManager: fieldManager})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			logf("REMEDIATE networkpolicy/%s was created concurrently by another writer — nothing to do", baselinePolicyName)
			return nil
		}
		var statusErr *apierrors.StatusError
		if errors.As(err, &statusErr) {
			return fmt.Errorf("creating networkpolicy/%s: %s", baselinePolicyName, statusErr.ErrStatus.Message)
		}
		return fmt.Errorf("creating networkpolicy/%s: %w", baselinePolicyName, err)
	}
	logf("REMEDIATE created networkpolicy/%s in %s uid=%s resourceVersion=%s — every pod is isolated for Ingress and Egress again",
		created.Name, namespace, created.UID, created.ResourceVersion)
	return nil
}

// baselineDefaultDeny is an in-code copy of network/00-default-deny.yaml.
// It carries no extra labels or annotations ON PURPOSE: the object this
// controller creates must be indistinguishable from the one `kubectl apply -f
// network/00-default-deny.yaml` creates, so remediation restores the repo's
// baseline rather than a controller-flavoured variant of it.
func baselineDefaultDeny(namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baselinePolicyName,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

func fmtList(items []string) string {
	return "[" + strings.Join(items, ",") + "]"
}
