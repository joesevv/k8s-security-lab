// Unit tests for the isolation model. These are the tests that matter: if
// Evaluate misreads NetworkPolicy selection semantics, the controller either
// cries wolf on a protected namespace or — far worse — reports HOLDS while a
// pod sits unprotected. The last case in TestEvaluate is the exact scenario
// phase 8 demonstrates against the live cluster, encoded as a fixture.
package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pod(name string, labels map[string]string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo", Labels: labels}}
}

// policy builds a NetworkPolicy with an EXPLICIT podSelector and policyTypes.
// Passing a nil label map yields podSelector {} — the empty selector that
// selects every pod in the namespace.
func policy(name string, matchLabels map[string]string, types ...networkingv1.PolicyType) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: matchLabels},
			PolicyTypes: types,
		},
	}
}

const (
	ingress = networkingv1.PolicyTypeIngress
	egress  = networkingv1.PolicyTypeEgress
)

type want struct {
	pod     string
	ingress bool
	egress  bool
}

func TestEvaluate(t *testing.T) {
	nginxPod := pod("nginx-1", map[string]string{"app": "nginx"})
	signedPod := pod("signed-app-1", map[string]string{"app": "signed-app"})
	unlabelledPod := pod("bare-1", nil)

	defaultDeny := policy("default-deny", nil, ingress, egress)
	allowDNS := policy("allow-dns", nil, egress)
	nginxIngress := policy("allow-nginx-ingress-from-client", map[string]string{"app": "nginx"}, ingress)
	clientEgress := policy("allow-client-egress-to-nginx", map[string]string{"access": "nginx"}, egress)

	cases := []struct {
		name     string
		pods     []corev1.Pod
		policies []networkingv1.NetworkPolicy
		want     []want
	}{
		{
			name:     "empty podSelector with both policyTypes isolates every pod, labelled or not",
			pods:     []corev1.Pod{nginxPod, signedPod, unlabelledPod},
			policies: []networkingv1.NetworkPolicy{defaultDeny},
			want: []want{
				{"nginx-1", true, true},
				{"signed-app-1", true, true},
				{"bare-1", true, true},
			},
		},
		{
			name:     "matching selector isolates only the pods it selects",
			pods:     []corev1.Pod{nginxPod, signedPod},
			policies: []networkingv1.NetworkPolicy{nginxIngress},
			want: []want{
				{"nginx-1", true, false},
				{"signed-app-1", false, false},
			},
		},
		{
			name:     "non-matching selector isolates nothing",
			pods:     []corev1.Pod{signedPod},
			policies: []networkingv1.NetworkPolicy{clientEgress},
			want:     []want{{"signed-app-1", false, false}},
		},
		{
			name:     "no policies at all: no pod is isolated in either direction",
			pods:     []corev1.Pod{nginxPod, signedPod},
			policies: nil,
			want: []want{
				{"nginx-1", false, false},
				{"signed-app-1", false, false},
			},
		},
		{
			name:     "one direction missing: an Egress-only policy leaves Ingress uncovered",
			pods:     []corev1.Pod{signedPod},
			policies: []networkingv1.NetworkPolicy{allowDNS},
			want:     []want{{"signed-app-1", false, true}},
		},
		{
			name:     "both directions, supplied by two different policies, union to isolated",
			pods:     []corev1.Pod{nginxPod},
			policies: []networkingv1.NetworkPolicy{allowDNS, nginxIngress},
			want:     []want{{"nginx-1", true, true}},
		},
		{
			name:     "the healthy demo namespace: all four policies present, invariant holds",
			pods:     []corev1.Pod{nginxPod, signedPod},
			policies: []networkingv1.NetworkPolicy{defaultDeny, allowDNS, nginxIngress, clientEgress},
			want: []want{
				{"nginx-1", true, true},
				{"signed-app-1", true, true},
			},
		},
		{
			// The phase-8 scenario. default-deny is gone; the other three
			// policies are untouched. nginx keeps Ingress from its own
			// policy and every pod keeps Egress from allow-dns, so exactly
			// ONE pod in ONE direction loses coverage.
			name:     "default-deny deleted: signed-app alone loses Ingress isolation",
			pods:     []corev1.Pod{nginxPod, signedPod},
			policies: []networkingv1.NetworkPolicy{allowDNS, nginxIngress, clientEgress},
			want: []want{
				{"nginx-1", true, true},
				{"signed-app-1", false, true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.pods, tc.policies)
			if err != nil {
				t.Fatalf("Evaluate returned an unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d verdicts, want %d", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].Name != w.pod {
					t.Fatalf("verdict %d is for pod %q, want %q", i, got[i].Name, w.pod)
				}
				if got[i].Ingress != w.ingress || got[i].Egress != w.egress {
					t.Errorf("pod %s: got ingress=%t egress=%t, want ingress=%t egress=%t (ingressBy=%v egressBy=%v)",
						w.pod, got[i].Ingress, got[i].Egress, w.ingress, w.egress, got[i].IngressBy, got[i].EgressBy)
				}
			}
		})
	}
}

// The log line names the policy responsible for each direction, so the
// attribution has to be right, not just the boolean.
func TestEvaluateAttributesPoliciesByName(t *testing.T) {
	got, err := Evaluate(
		[]corev1.Pod{pod("nginx-1", map[string]string{"app": "nginx"})},
		[]networkingv1.NetworkPolicy{
			policy("allow-nginx-ingress-from-client", map[string]string{"app": "nginx"}, ingress),
			policy("allow-dns", nil, egress),
			policy("default-deny", nil, ingress, egress),
		},
	)
	if err != nil {
		t.Fatalf("Evaluate returned an unexpected error: %v", err)
	}
	wantIngress := []string{"allow-nginx-ingress-from-client", "default-deny"}
	wantEgress := []string{"allow-dns", "default-deny"}
	if !equal(got[0].IngressBy, wantIngress) {
		t.Errorf("ingressBy = %v, want %v (sorted)", got[0].IngressBy, wantIngress)
	}
	if !equal(got[0].EgressBy, wantEgress) {
		t.Errorf("egressBy = %v, want %v (sorted)", got[0].EgressBy, wantEgress)
	}
}

func TestMissing(t *testing.T) {
	cases := []struct {
		name string
		in   PodIsolation
		want []string
	}{
		{"both directions covered", PodIsolation{Ingress: true, Egress: true}, nil},
		{"ingress missing", PodIsolation{Ingress: false, Egress: true}, []string{"Ingress"}},
		{"egress missing", PodIsolation{Ingress: true, Egress: false}, []string{"Egress"}},
		{"both missing", PodIsolation{}, []string{"Ingress", "Egress"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Missing(); !equal(got, tc.want) {
				t.Errorf("Missing() = %v, want %v", got, tc.want)
			}
			if got, want := tc.in.Violated(), len(tc.want) > 0; got != want {
				t.Errorf("Violated() = %t, want %t", got, want)
			}
		})
	}
}

// policyTypes is optional in the API. If this defaulting were wrong the
// controller would over-report isolation on any policy written without it.
func TestEffectivePolicyTypes(t *testing.T) {
	withEgressRule := networkingv1.NetworkPolicy{
		Spec: networkingv1.NetworkPolicySpec{
			Egress: []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}
	cases := []struct {
		name        string
		in          networkingv1.NetworkPolicy
		wantIngress bool
		wantEgress  bool
	}{
		{"explicit Ingress+Egress", policy("p", nil, ingress, egress), true, true},
		{"explicit Ingress only", policy("p", nil, ingress), true, false},
		{"explicit Egress only", policy("p", nil, egress), false, true},
		{"absent policyTypes, no egress rules: Ingress is implied", policy("p", nil), true, false},
		{"absent policyTypes, egress rules present: Ingress+Egress implied", withEgressRule, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotIngress, gotEgress := effectivePolicyTypes(tc.in)
			if gotIngress != tc.wantIngress || gotEgress != tc.wantEgress {
				t.Errorf("effectivePolicyTypes() = (ingress=%t, egress=%t), want (ingress=%t, egress=%t)",
					gotIngress, gotEgress, tc.wantIngress, tc.wantEgress)
			}
		})
	}
}

// baselineDefaultDeny must stay byte-compatible with
// network/00-default-deny.yaml: an empty podSelector and both policyTypes,
// with no rules. If someone "improves" it, remediation stops restoring the
// repo's baseline and starts installing something else.
func TestBaselineDefaultDenyMatchesTheCommittedBaseline(t *testing.T) {
	np := baselineDefaultDeny("demo")
	if np.Name != "default-deny" || np.Namespace != "demo" {
		t.Errorf("got %s/%s, want demo/default-deny", np.Namespace, np.Name)
	}
	if len(np.Spec.PodSelector.MatchLabels) != 0 || len(np.Spec.PodSelector.MatchExpressions) != 0 {
		t.Errorf("podSelector must be empty (select every pod), got %+v", np.Spec.PodSelector)
	}
	if !equalTypes(np.Spec.PolicyTypes, []networkingv1.PolicyType{ingress, egress}) {
		t.Errorf("policyTypes = %v, want [Ingress Egress]", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		t.Errorf("the baseline must carry NO allow rules, got ingress=%v egress=%v", np.Spec.Ingress, np.Spec.Egress)
	}
	if len(np.Labels) != 0 || len(np.Annotations) != 0 {
		t.Errorf("the created object must be indistinguishable from the applied file: labels=%v annotations=%v", np.Labels, np.Annotations)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalTypes(a, b []networkingv1.PolicyType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
