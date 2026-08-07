// Phase 8 — the isolation model.
//
// This file is deliberately PURE: it takes the objects the apiserver already
// returned and answers one question per pod, with no cluster calls and no
// hidden state. That is why it is the part that carries unit tests
// (isolation_test.go) — the correctness of the whole controller reduces to
// whether these functions reproduce Kubernetes NetworkPolicy semantics.
//
// The semantics being reproduced (networking.k8s.io/v1):
//   - A pod is "isolated" for a direction if ANY NetworkPolicy in its
//     namespace selects it AND lists that direction in policyTypes.
//   - Selection uses label-selector semantics, NOT string equality: an EMPTY
//     podSelector ({}) selects every pod in the namespace. This is why
//     metav1.LabelSelectorAsSelector is used rather than hand-rolled map
//     comparison — an empty selector must become labels.Everything().
//   - Isolation is about whether a policy applies at all, NOT about what its
//     rules allow. A policy that isolates a pod and then allows 0.0.0.0/0
//     still counts as isolated here. See README.md "What it does not check".
package main

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// PodIsolation is the verdict for a single pod: whether it is isolated in each
// direction, and which policies are responsible. The "By" slices exist for the
// log line — naming the policy that provides the coverage is what makes the
// evidence readable when one of them is deleted.
type PodIsolation struct {
	Name      string
	Ingress   bool
	Egress    bool
	IngressBy []string
	EgressBy  []string
}

// Missing returns the directions this pod is NOT isolated for, in a stable
// order (Ingress before Egress) so log lines are comparable across scans.
func (p PodIsolation) Missing() []string {
	var missing []string
	if !p.Ingress {
		missing = append(missing, "Ingress")
	}
	if !p.Egress {
		missing = append(missing, "Egress")
	}
	return missing
}

// Violated reports whether the invariant fails for this pod.
func (p PodIsolation) Violated() bool { return !p.Ingress || !p.Egress }

// effectivePolicyTypes resolves the directions a policy actually governs.
//
// policyTypes is optional in the API. When it is absent the documented default
// is: Ingress always, plus Egress if and only if the policy carries egress
// rules. The apiserver normally defaults the field on write, so live objects
// have it set — but a policy read from a file, or from an older writer, may
// not, and getting this wrong would silently over- or under-count isolation.
func effectivePolicyTypes(np networkingv1.NetworkPolicy) (ingress bool, egress bool) {
	if len(np.Spec.PolicyTypes) > 0 {
		for _, t := range np.Spec.PolicyTypes {
			switch t {
			case networkingv1.PolicyTypeIngress:
				ingress = true
			case networkingv1.PolicyTypeEgress:
				egress = true
			}
		}
		return ingress, egress
	}
	return true, len(np.Spec.Egress) > 0
}

// Evaluate computes the isolation verdict for every pod against every policy.
// Results come back in the order the pods were given; the "By" slices are
// sorted by policy name so repeated scans produce identical text.
//
// An error is returned only if a policy carries a podSelector the apiserver
// itself could not have accepted (malformed matchExpressions); a bad selector
// is reported rather than silently treated as "matches nothing", because
// "matches nothing" would understate isolation and hide the invariant failing.
func Evaluate(pods []corev1.Pod, policies []networkingv1.NetworkPolicy) ([]PodIsolation, error) {
	type compiled struct {
		name     string
		selector labels.Selector
		ingress  bool
		egress   bool
	}

	compiledPolicies := make([]compiled, 0, len(policies))
	for i := range policies {
		np := policies[i]
		selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("networkpolicy %q has an unusable podSelector: %w", np.Name, err)
		}
		ingress, egress := effectivePolicyTypes(np)
		compiledPolicies = append(compiledPolicies, compiled{
			name:     np.Name,
			selector: selector,
			ingress:  ingress,
			egress:   egress,
		})
	}

	results := make([]PodIsolation, 0, len(pods))
	for i := range pods {
		pod := pods[i]
		verdict := PodIsolation{Name: pod.Name}
		podLabels := labels.Set(pod.Labels)

		for _, cp := range compiledPolicies {
			if !cp.selector.Matches(podLabels) {
				continue
			}
			if cp.ingress {
				verdict.Ingress = true
				verdict.IngressBy = append(verdict.IngressBy, cp.name)
			}
			if cp.egress {
				verdict.Egress = true
				verdict.EgressBy = append(verdict.EgressBy, cp.name)
			}
		}

		sort.Strings(verdict.IngressBy)
		sort.Strings(verdict.EgressBy)
		results = append(results, verdict)
	}

	return results, nil
}
