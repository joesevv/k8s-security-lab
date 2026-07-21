# Kyverno install record — Phase 2b admission control

Installed 2026-07-21 on the kind `seclab` cluster (context `kind-seclab`,
Kubernetes v1.35.5).

## Exact commands

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm search repo kyverno -l | grep -E "1\.18"   # resolve chart for app 1.18.x
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace --version 3.8.2
```

## Pinned versions (observed)

| What | Value |
| --- | --- |
| Helm chart | `kyverno/kyverno` **3.8.2** (pinned via `--version`) |
| App version | **v1.18.2** (`helm list -n kyverno` APP VERSION) |
| Admission controller image | `reg.kyverno.io/kyverno/kyverno:v1.18.2` |

`helm list -n kyverno`:

```
NAME   	NAMESPACE	REVISION	UPDATED                              	STATUS  	CHART        	APP VERSION
kyverno	kyverno  	1       	2026-07-21 08:50:15.7202603 -0500 CDT	deployed	kyverno-3.8.2	v1.18.2
```

All four controllers (admission, background, cleanup, reports) rolled out and
Ready within ~60s.

## Served ValidatingPolicy apiVersion (resolved on-cluster)

`kubectl api-resources | grep -i validatingpolic`:

```
imagevalidatingpolicies             ivpol        policies.kyverno.io/v1            false        ImageValidatingPolicy
namespacedimagevalidatingpolicies   nivpol       policies.kyverno.io/v1            true         NamespacedImageValidatingPolicy
namespacedvalidatingpolicies        nvpol        policies.kyverno.io/v1            true         NamespacedValidatingPolicy
validatingpolicies                  vpol         policies.kyverno.io/v1            false        ValidatingPolicy
```

The cluster serves **`policies.kyverno.io/v1`** (the policy-library examples
show `v1alpha1`; on Kyverno 1.18.2 the storage/served version is `v1`). All
policies in `policies/` therefore use `apiVersion: policies.kyverno.io/v1`.
Key spec fields confirmed via `kubectl explain validatingpolicy.spec`:
`matchConstraints`, `variables`, `validations`, `validationActions`
(values `Audit` / `Warn` / `Deny` — there is no `validationFailureAction`).
