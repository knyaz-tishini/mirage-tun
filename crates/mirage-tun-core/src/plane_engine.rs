use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use crate::plane::{Plane, ProcessIdentity};
use crate::policy::{PolicyDecision, FailurePolicy, PolicyEngine};
use crate::wire_health::WireHealthMap;

#[derive(Debug, Error)]
pub enum PlaneEngineError {
    #[error("unresolved Group plane passed to enforce — resolve_group must be called first")]
    UnresolvedGroup,
    #[error("policy engine unavailable")]
    PolicyUnavailable,
}

/// The platform-agnostic kill-switch / bypass / per-wire isolation engine.
///
/// Owns:
/// - `Arc<PolicyEngine>` — destination-based + process-based rule evaluation (unchanged)
/// - `Arc<WireHealthMap>` — per-wire liveness (unchanged)
///
/// Resolves `ProcessIdentity → Plane` respecting all 3 invariants + fail-closed semantics.
/// One instance lives in the TUN stack, shared via `Arc`; platform executors hold a clone.
pub struct PlaneEngine {
    policy: Arc<PolicyEngine>,
    health: Arc<WireHealthMap>,
}

impl PlaneEngine {
    pub fn new(policy: Arc<PolicyEngine>, health: Arc<WireHealthMap>) -> Self {
        Self { policy, health }
    }

    /// Resolve a flow to a `Plane`.
    ///
    /// # Decision order (invariants enforced here, not in platform code)
    ///
    /// 1. Call `PolicyEngine::get_config().await` → `Arc<CompiledPolicy>`.
    ///    Then call `decide_full(dst_ip, dst_port, domain_hint, app_info)`.
    /// 2. Map `action` to initial plane:
    ///    - `Bypass`         → `Plane::Bypass`  (invariant 1: this can never become Kill)
    ///    - `Chain(id)`      → check `failure_policy`:
    ///      - `FailClosed`      → `Plane::Wire(id)` (pinned; down = Kill)
    ///      - `Failover{group}` → `Plane::Group(group)` (any healthy in group; all-down = Kill)
    /// 3. For `Plane::Wire(id)`: query `WireHealthMap::is_healthy(id)`.
    ///    - Healthy   → `Plane::Wire(id)` (pass through).
    ///    - Unhealthy → `Plane::Kill` (fail-closed; invariant 2: no native internet fallback).
    /// 4. For `Plane::Group(group)`: caller must consult `resolve_group` with candidates.
    /// 5. `Plane::Bypass` is NEVER demoted to Kill (invariant 1).
    ///
    /// # Unattributed flows
    /// `identity = None` → uses the compiled policy's default_action. The same mapping
    /// applies. Fail-closed default_action = `Chain("default")` → `Plane::Wire("default")`.
    pub async fn resolve(
        &self,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        identity: Option<&ProcessIdentity>,
    ) -> Plane {
        let app_info = identity.map(|id| &id.info);
        let cfg = self.policy.get_config().await;
        let rd = cfg.decide_full(dst_ip, dst_port, domain_hint, app_info);
        self.routing_decision_to_plane(rd)
    }

    /// Pure synchronous variant for use from `spawn_blocking` or tests.
    pub fn resolve_sync(
        &self,
        routing_decision: crate::policy::RoutingDecision,
    ) -> Plane {
        self.routing_decision_to_plane(routing_decision)
    }

    fn routing_decision_to_plane(
        &self,
        rd: crate::policy::RoutingDecision,
    ) -> Plane {
        match rd.action {
            // Invariant 1: Bypass is sacred — never demoted.
            PolicyDecision::Bypass => Plane::Bypass,

            PolicyDecision::Chain(id) => {
                match rd.failure_policy {
                    FailurePolicy::FailClosed => {
                        // Pinned wire. Check health now.
                        // Invariant 2: unhealthy wire → Kill (no native fallback ever).
                        if self.health.is_healthy(&id) {
                            Plane::Wire(id)
                        } else {
                            Plane::Kill
                        }
                    }
                    FailurePolicy::Failover { group } => {
                        // Group wire. Resolution deferred to caller via resolve_group.
                        // Return Group sentinel — caller feeds candidate list.
                        Plane::Group(group)
                    }
                }
            }
        }
    }

    /// Resolve a `Plane::Group` to a concrete `Plane::Wire` or `Plane::Kill`.
    ///
    /// Called by the accept loop after `resolve()` returns `Plane::Group(g)`.
    /// `candidates` = ordered list of (wire_id, endpoint) for group `g`.
    /// Returns `Plane::Wire(first_healthy)` or `Plane::Kill` (all down = fail-closed).
    /// Invariant 3: NEVER returns Bypass as a fallback.
    pub fn resolve_group(
        &self,
        _group: &str,
        candidates: &[(String, SocketAddr)],
    ) -> Plane {
        match self.health.first_healthy(candidates) {
            Some((wire_id, _addr)) => Plane::Wire(wire_id.clone()),
            None => Plane::Kill, // all wires in group down — fail-closed
        }
    }

    /// Expose the wire health map so platform executors can call record_success / record_failure.
    pub fn health(&self) -> &Arc<WireHealthMap> {
        &self.health
    }

    /// Expose the policy engine for config updates.
    pub fn policy(&self) -> &Arc<PolicyEngine> {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::policy::{CompiledPolicy, PolicyDecision, PolicyRule, FailurePolicy, WireClass};

    fn sa(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn engine_with_policy(policy: CompiledPolicy) -> PlaneEngine {
        let pe = Arc::new(PolicyEngine::new(policy));
        let wh = WireHealthMap::new();
        PlaneEngine::new(pe, wh)
    }

    fn engine_with_policy_and_health(policy: CompiledPolicy) -> (PlaneEngine, Arc<WireHealthMap>) {
        let pe = Arc::new(PolicyEngine::new(policy));
        let wh = WireHealthMap::new();
        let wh_clone = wh.clone();
        (PlaneEngine::new(pe, wh), wh_clone)
    }

    fn cidr_rule(cidr: &str, action: PolicyDecision) -> PolicyRule {
        PolicyRule::DestCidr {
            cidr: cidr.to_owned(),
            action,
            failure_policy: FailurePolicy::default(),
            wire_class: WireClass::default(),
        }
    }

    fn cidr_rule_with_fp(cidr: &str, action: PolicyDecision, fp: FailurePolicy) -> PolicyRule {
        PolicyRule::DestCidr {
            cidr: cidr.to_owned(),
            action,
            failure_policy: fp,
            wire_class: WireClass::default(),
        }
    }

    /// `PolicyDecision::Bypass` → `Plane::Bypass` regardless of wire health state.
    #[test]
    fn bypass_never_demoted_to_kill() {
        let rules = vec![cidr_rule("10.0.0.0/8", PolicyDecision::Bypass)];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        let engine = engine_with_policy(policy);
        let rd = crate::policy::RoutingDecision {
            action: PolicyDecision::Bypass,
            failure_policy: FailurePolicy::FailClosed,
            wire_class: WireClass::default(),
        };
        assert_eq!(engine.resolve_sync(rd), Plane::Bypass);
    }

    /// `Chain("a") + FailClosed` with healthy wire → `Plane::Wire("a")`.
    #[test]
    fn pinned_wire_healthy() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let (engine, health) = engine_with_policy_and_health(policy);
        health.record_success("a");
        let rd = crate::policy::RoutingDecision {
            action: PolicyDecision::Chain("a".to_owned()),
            failure_policy: FailurePolicy::FailClosed,
            wire_class: WireClass::default(),
        };
        assert_eq!(engine.resolve_sync(rd), Plane::Wire("a".to_owned()));
    }

    /// `Chain("a") + FailClosed` + two consecutive failures → `Plane::Kill`.
    #[test]
    fn pinned_wire_down_returns_kill() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let (engine, health) = engine_with_policy_and_health(policy);
        health.record_failure("a");
        health.record_failure("a");
        let rd = crate::policy::RoutingDecision {
            action: PolicyDecision::Chain("a".to_owned()),
            failure_policy: FailurePolicy::FailClosed,
            wire_class: WireClass::default(),
        };
        assert_eq!(engine.resolve_sync(rd), Plane::Kill);
    }

    /// `Chain("b") + Failover{group:"g"}` + all candidates unhealthy → `Plane::Kill`.
    #[test]
    fn group_all_down_returns_kill() {
        let fp = FailurePolicy::Failover { group: "g".to_owned() };
        let rules = vec![cidr_rule_with_fp("10.0.0.0/8", PolicyDecision::Chain("b".to_owned()), fp)];
        let policy = CompiledPolicy::compile(rules, PolicyDecision::default_chain());
        let (engine, health) = engine_with_policy_and_health(policy);
        // Mark both candidates unhealthy.
        health.record_failure("wire1");
        health.record_failure("wire1");
        health.record_failure("wire2");
        health.record_failure("wire2");
        let candidates = vec![
            ("wire1".to_owned(), sa(1080)),
            ("wire2".to_owned(), sa(1081)),
        ];
        let plane = engine.resolve_group("g", &candidates);
        assert_eq!(plane, Plane::Kill);
    }

    /// `Failover{group:"g"}` + one healthy candidate → `Plane::Wire(that_candidate)`.
    #[test]
    fn group_first_healthy_returns_wire() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let (engine, health) = engine_with_policy_and_health(policy);
        // wire1 unhealthy, wire2 healthy.
        health.record_failure("wire1");
        health.record_failure("wire1");
        health.record_success("wire2");
        let candidates = vec![
            ("wire1".to_owned(), sa(1080)),
            ("wire2".to_owned(), sa(1081)),
        ];
        let plane = engine.resolve_group("g", &candidates);
        assert_eq!(plane, Plane::Wire("wire2".to_owned()));
    }

    /// `identity=None` with default_action=Chain("default") → `Plane::Wire("default")`.
    /// "default" wire absent from health map → is_healthy returns true (absent = healthy).
    #[test]
    fn unattributed_flow_uses_default() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let engine = engine_with_policy(policy);
        let rd = crate::policy::RoutingDecision {
            action: PolicyDecision::Chain("default".to_owned()),
            failure_policy: FailurePolicy::FailClosed,
            wire_class: WireClass::default(),
        };
        // "default" wire is absent from health map → is_healthy("default") = true.
        assert_eq!(engine.resolve_sync(rd), Plane::Wire("default".to_owned()));
    }

    /// Even if the rule's `failure_policy=FailClosed`, a `Bypass` action → `Plane::Bypass`.
    /// Invariant 1 must hold regardless of the failure_policy field value.
    #[test]
    fn bypass_invariant_1_with_failclosed_fp() {
        let policy = CompiledPolicy::compile(vec![], PolicyDecision::default_chain());
        let engine = engine_with_policy(policy);
        // Construct a RoutingDecision with action=Bypass AND failure_policy=FailClosed.
        // Even though FailClosed normally means "kill on wire down", Bypass wins.
        let rd = crate::policy::RoutingDecision {
            action: PolicyDecision::Bypass,
            failure_policy: FailurePolicy::FailClosed,
            wire_class: WireClass::default(),
        };
        assert_eq!(engine.resolve_sync(rd), Plane::Bypass);
    }
}
