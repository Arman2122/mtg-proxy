//! Governance, rate limiting, fair-share scheduling, per-secret/per-address
//! quotas, IP bans, FakeTLS hints/scan budget, lock-free anti-replay, and
//! wait-free DIR-24-8 IP blocklist/allowlist for `mtg-proxy`.

pub mod address_ledger;
pub mod antireplay;
pub mod bans;
pub mod client_table;
pub mod hints;
pub mod ipfilter;
pub mod rate_limit;
pub mod scan_budget;
pub mod secret_set;

pub use address_ledger::{
    AddressRegistry, AddressReport, ConnHandle, DEFAULT_EXTERNAL_ADDRESS_TTL, ExternalAddressError,
    LedgerDeny, MAX_EXTERNAL_ADDRESS_TTL, MAX_EXTERNAL_ADDRESSES, parse_external_addresses,
};
pub use antireplay::{FakeTlsAntiReplay, Obfs2AntiReplay};
pub use bans::{
    BanEntryJson, BanError, BanList, DEFAULT_BAN_TTL, MAX_BAN_TTL, MAX_BANS, parse_ban_request,
    parse_ban_unit,
};
pub use client_table::{
    CLIENT_IDLE_RETENTION_SECS, CLIENT_SWEEP_CHUNK, CLIENT_SWEEP_INTERVAL, ClientCounts,
    ClientEntry, ClientTable, ClientsView, EntryInit, FairShareScratch, MAX_CLIENTS,
    MAX_CLIENTS_PER_SECRET,
};
pub use hints::{
    HANDSHAKE_BUCKET_ROTATION, HANDSHAKE_BURST_FACTOR, HINT_ROTATION, MAX_HINT_ADDRESSES,
    MAX_HINT_NAMES, MAX_HINT_POSITIONS, MAX_SCAN_BLOCKS, MAX_TRACKED_HANDSHAKE_IPS, MatchHints,
    ObfuscatedLimiter, hint_key,
};
pub use ipfilter::{
    DEFAULT_IPFILTER_UPDATE_EACH, IpFilter, IpFilterBuilder, IpFilterError, LiveIpFilter,
};
pub use rate_limit::{
    ADDR_BURST_DIVISOR, BlockedTracker, DEMAND_INFINITE, FAIR_ACTIVE_WINDOW_NS, FAIR_HOLD_TICKS,
    FAIR_THROTTLE_DIVISOR, FAIR_TICK_INTERVAL, FairBucket, FairEntryInput, FairVerdict,
    GcraLimiter, MAX_ADDR_BURST, MIN_ADDR_BURST, addr_burst, decide_fair_share,
    jains_fairness_index, secret_burst, water_level,
};
pub use scan_budget::{
    BUDGET_ROTATION, BURST_FLOOR_HELLOS, BudgetVerdict, DEFAULT_BUDGET_CPU_PERCENT,
    DEFAULT_BUDGET_MAX_WAIT, DEFAULT_BUDGET_PER_IP_MS, MAX_BUDGET_ADDRESSES,
    MAX_BUDGET_CPU_PERCENT, MAX_BUDGET_PER_IP_MS, MIN_COST_BLOCKS, ScanBudget, ScanBudgetConfig,
    ScanReservation, calibrated_block_nanos,
};
pub use secret_set::{
    FairSecretSpec, HostedCandidate, Obfs2Candidate, SecretRecord, SecretSet, SniBucket,
};

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use mtg_core::{FairTotals, IpUnit};

    use super::*;

    #[test]
    fn address_registry_enforces_ip_limit_client_conns_and_ok_kick_lookup() {
        let reg = AddressRegistry::new();
        let now = Utc::now();
        let ip1: IpAddr = "203.0.113.10".parse().unwrap();
        let ip2: IpAddr = "203.0.113.11".parse().unwrap();
        let ip3: IpAddr = "203.0.113.12".parse().unwrap();

        let h1 = ConnHandle {
            worker_id: 0,
            conn_id: 1,
        };
        let h2 = ConnHandle {
            worker_id: 1,
            conn_id: 2,
        };
        let h3 = ConnHandle {
            worker_id: 0,
            conn_id: 3,
        };
        let h4 = ConnHandle {
            worker_id: 0,
            conn_id: 4,
        };

        // Limit: 2 distinct IPs, 2 conns per IP
        reg.admit_and_register("alice", h1, Some(ip1), 2, 2, true, now)
            .unwrap();
        reg.admit_and_register("alice", h2, Some(ip1), 2, 2, true, now)
            .unwrap();
        // 3rd conn from ip1 hits client_conns!
        assert_eq!(
            reg.admit_and_register("alice", h3, Some(ip1), 2, 2, true, now),
            Err(LedgerDeny::ClientConns)
        );
        // 2nd distinct IP succeeds
        reg.admit_and_register("alice", h3, Some(ip2), 2, 2, true, now)
            .unwrap();
        // 3rd distinct IP hits ip_limit!
        assert_eq!(
            reg.admit_and_register("alice", h4, Some(ip3), 2, 2, true, now),
            Err(LedgerDeny::IpLimit)
        );

        // O(K) lookup returns exactly ip1's 2 handles!
        let kicked = reg.handles_for_units("alice", &[IpUnit::from_ip(ip1)]);
        assert_eq!(kicked.len(), 2);
        assert!(kicked.contains(&h1) && kicked.contains(&h2));

        // External IP counts against union
        reg.unregister("alice", h3, now);
        reg.set_external("alice", &[ip2], Duration::from_secs(60), now);
        assert_eq!(
            reg.admit_and_register("alice", h4, Some(ip3), 2, 2, true, now),
            Err(LedgerDeny::IpLimit)
        );
    }

    #[test]
    fn ban_list_enforces_force_guard_ttl_and_atomic_fast_path() {
        let bans = BanList::new();
        let now = Utc::now();
        assert!(bans.is_empty_fast());

        // Loopback refused without force=true
        assert!(parse_ban_request(&["127.0.0.1".to_owned()], "1h", false).is_err());
        let (units, ttl) =
            parse_ban_request(&["2001:db8:1:2::99".to_owned()], "1h", false).unwrap();
        assert_eq!(units[0].to_string(), "2001:db8:1:2::/64");

        bans.add("alice", &units, ttl, now).unwrap();
        assert!(!bans.is_empty_fast());
        // Any address in the same /64 is banned!
        let sibling = IpUnit::from_ip("2001:db8:1:2::abcd".parse().unwrap());
        assert!(bans.is_banned("alice", sibling, now));
        assert!(!bans.is_banned("bob", sibling, now));

        // Lapses cleanly after TTL
        let later = now + chrono::Duration::hours(2);
        assert!(!bans.is_banned("alice", sibling, later));
        assert!(bans.is_empty_fast());
    }

    #[test]
    fn client_table_fair_share_tick_converges_and_sweeps_idle_entries() {
        let table = ClientTable::new();
        let alice: Arc<str> = Arc::from("alice");
        let totals = FairTotals {
            speed: 10_000_000,
            up: 0,
            down: 0,
        };
        let init = EntryInit {
            ceiling_rate: 0,
            fair_totals: totals,
        };
        let u1 = IpUnit::from_ip("198.51.100.1".parse().unwrap());
        let u2 = IpUnit::from_ip("198.51.100.2".parse().unwrap());

        let e1 = table.acquire_at(&alice, Some(u1), true, init, 1000);
        let e2 = table.acquire_at(&alice, Some(u2), true, init, 1000);

        let spec = FairSecretSpec {
            name: Arc::clone(&alice),
            totals,
        };
        let mut scratch = FairShareScratch::default();

        // Tick 1: baseline
        table.tick_secret(1_000_000_000, &spec, &mut scratch);

        // Both entries blocked for 500ms during tick 2 -> both throttled -> 5 MB/s each!
        e1.fair_blocked(FairBucket::Speed).enter(1_200_000_000);
        e1.fair_blocked(FairBucket::Speed).leave(1_700_000_000);
        e2.fair_blocked(FairBucket::Speed).enter(1_200_000_000);
        e2.fair_blocked(FairBucket::Speed).leave(1_700_000_000);

        table.tick_secret(2_000_000_000, &spec, &mut scratch);
        assert_eq!(e1.fair_limiter(FairBucket::Speed).rate_bps(), 5_000_000);
        assert_eq!(e2.fair_limiter(FairBucket::Speed).rate_bps(), 5_000_000);

        // Release and sweep after 11 minutes
        table.release_at(&e1, 1000);
        table.release_at(&e2, 1000);
        assert_eq!(table.sweep(1000 + 660, 1024), 2);
    }

    #[test]
    fn hints_and_scan_budget_refund_on_match() {
        let hints = MatchHints::new(true);
        let ip: IpAddr = "198.51.100.55".parse().unwrap();
        hints.remember(ip, Arc::from("alice"));
        hints.remember(ip, Arc::from("bob"));
        let recalled = hints.recall(ip);
        assert_eq!(recalled.len(), 2);
        assert_eq!(recalled[0].as_ref(), "bob");
        assert_eq!(recalled[1].as_ref(), "alice");

        let budget = ScanBudget::new(ScanBudgetConfig::default());
        assert!(budget.block_nanos() >= 10.0 && budget.block_nanos() <= 2000.0);
        let (res, _wait, verdict) = budget.reserve(ip, 12, 100);
        assert_eq!(verdict, BudgetVerdict::Granted);
        let mut r = res.unwrap();
        r.settle(&budget, true);
    }
}
