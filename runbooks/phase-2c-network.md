# Runbook — Phase 2c: Network policies (default-deny + explicit allow)

A replayable command log for the network layer: four `NetworkPolicy`
resources in the `demo` namespace implementing default-deny on both ingress
and egress, a DNS carve-out, and a label-based allow-list for nginx — then a
live attack proving that an unlabeled pod's connection to nginx times out
while an otherwise-identical labeled pod gets HTTP 200. Commands are listed
in execution order; each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, CNI kindnet.

**Enforcement caveat, validated up front:** kind's default kindnet CNI
historically did not implement NetworkPolicy, in which case every policy
below would be silently ignored. On this cluster kindnet DOES enforce it —
confirmed empirically before this phase (a default-deny-ingress policy
flipped a cross-node curl from 200 to a timeout). Everything below is real
observed enforcement, not assumed.

---

## 0. The controls

Four `networking.k8s.io/v1` NetworkPolicies in `network/`, numbered by apply
order so the deny-then-allow model reads top to bottom:

- **00-default-deny** — `podSelector: {}` with `policyTypes: [Ingress,
  Egress]` and no rules: every pod in `demo` is denied all ingress AND all
  egress until a later policy explicitly allows it.
- **10-allow-dns** — the DNS carve-out. Egress from all demo pods to the
  CoreDNS pods (`kube-system`, label `k8s-app=kube-dns`) on 53/UDP and
  53/TCP only. **Why it is needed:** default-deny egress otherwise blocks
  the resolver, so every name lookup fails and even "allowed" destinations
  break at the resolve step — a classic default-deny-egress footgun. **Why
  selecting the pod works:** clients dial the ClusterIP VIP (10.96.0.10),
  but kube-proxy DNATs the VIP to a CoreDNS pod IP before the egress policy
  is evaluated, and egress `to` selectors match the destination pod IP.
- **20-allow-nginx-ingress-from-client** — pods labeled `app=nginx` accept
  ingress only from pods labeled `access=nginx`, only on TCP 8080 (the
  container port behind the Service's port 80).
- **30-allow-client-egress-to-nginx** — pods labeled `access=nginx` may
  send egress to `app=nginx` pods on TCP 8080. Under default-deny both
  directions must be opened: 30 lets the client's packets out, 20 lets them
  into nginx.

Least-privilege throughout: no allow-all rules, no CIDR blocks, and the
`access=nginx` label is the **sole discriminator** between an allowed
client and a blocked one.

---

## 1. Safety sequence — deny baseline first, then the allows

Applying default-deny alone first proves the deny baseline itself is safe:
NetworkPolicy affects connections, not pod lifecycle, so running pods stay
Running.

```bash
kubectl apply -f network/00-default-deny.yaml
kubectl get pods -n demo
# NAME                     READY   STATUS    RESTARTS   AGE
# nginx-6d4cf656c9-8fkgn   1/1     Running   0          17m
# nginx-6d4cf656c9-t79g6   1/1     Running   0          17m

kubectl apply -f network/
# default-deny unchanged; allow-dns, allow-nginx-ingress-from-client,
# allow-client-egress-to-nginx created

kubectl get networkpolicy -n demo
# NAME                              POD-SELECTOR   AGE
# allow-client-egress-to-nginx      access=nginx   ...
# allow-dns                         <none>         ...
# allow-nginx-ingress-from-client   app=nginx      ...
# default-deny                      <none>         ...
```

---

## 2. Attack demo — unlabeled pod blocked, labeled pod allowed

Two test pods in `docs/evidence/phase-2c-network/`, identical in every way
(image `curlimages/curl:8.11.1` pinned, restricted securityContext — both
must and do pass the four Kyverno Deny policies from phase 2b at admission)
except one label:

- `attacker-unauthorized.yaml` — pod `unauth`, **no** `access` label.
- `client-authorized.yaml` — pod `authorized`, **with** `access: "nginx"`.

```bash
cd docs/evidence/phase-2c-network
kubectl apply -f attacker-unauthorized.yaml -f client-authorized.yaml
kubectl wait --for=condition=Ready pod/unauth pod/authorized -n demo --timeout=120s
```

**2a. DNS carve-out works** (so nothing below can be blamed on DNS):

```bash
kubectl exec -n demo authorized -- nslookup nginx.demo.svc.cluster.local
# Name:    nginx.demo.svc.cluster.local
# Address: 10.96.196.39
```

**2b. ATTACK — the unauthorized pod is blocked.** Same DNS name, same curl;
`-m 5` turns the NetworkPolicy drop into a visible 5-second timeout:

```bash
kubectl exec -n demo unauth -- curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://nginx.demo.svc.cluster.local/
# HTTP:000 time=5.002630
# command terminated with exit code 28   (curl 28 = timeout)
```

The `unauth` pod can still resolve the name (same nslookup succeeds from
it — captured in the evidence file), so the failure is the NetworkPolicy
denying the TCP connection, not a DNS failure.

**2c. CONTROL — the authorized pod gets through.** Identical command, only
the pod's label differs:

```bash
kubectl exec -n demo authorized -- curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://nginx.demo.svc.cluster.local/
# HTTP:200 time=0.002270
```

(Through `kubectl exec` from the Windows client, curl here reports exit 23
— a write error flushing the final `-w` line through the closing exec
stream — despite the HTTP:200. The same command inside the pod's own shell
exits 0; both forms are captured in the evidence file.)

Timeout vs. 2-millisecond 200, same name, same command, one label of
difference: the label-based NetworkPolicy is the discriminator. Full
verbatim captures: `docs/evidence/phase-2c-network/attack-output.txt`.

---

## 3. Teardown

The test pods are removed; the manifests and evidence stay committed so the
demo is replayable. The NetworkPolicies stay in place — they are the layer.

```bash
kubectl delete pod unauth authorized -n demo
kubectl get pods -n demo
# NAME                     READY   STATUS    RESTARTS   AGE
# nginx-6d4cf656c9-8fkgn   1/1     Running   0          23m
# nginx-6d4cf656c9-t79g6   1/1     Running   0          23m
```

To remove the layer itself (not done for the lab):

```bash
kubectl delete -f network/
```
