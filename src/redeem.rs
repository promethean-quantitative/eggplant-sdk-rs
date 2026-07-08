//! Redeem every resolved position a wallet holds, draining the redeemable
//! set to empty in gas-bounded relayer batches.
//!
//! [`DataApiClient::all_redeemable_positions`](crate::data::DataApiClient::all_redeemable_positions)
//! reports which of a wallet's positions have resolved and can be redeemed;
//! [`redeem_all`] collects them all and dispatches each to the right on-chain
//! redeem call for its market shape — a multi-outcome condition through the
//! adapter with its exact held amounts, a binary condition through the CTF
//! with its outcome index sets. Both need the wallet's on-chain balances, read
//! here in one batched `balanceOfBatch` per pass (the Data API's `size` is a
//! float and would misround the raw unit) — to size the adapter redeems, and
//! to skip conditions the wallet no longer holds. A too-high amount, or a
//! wrong outcome order, reverts on-chain, so a mis-built call fails safe
//! instead of losing funds.
//!
//! Redeeming is idempotent: a redeemed position drops out of the `redeemable`
//! filter, so a re-fetch never returns it twice. That, plus the Data API's
//! offset cap (see [`crate::data`]), is why [`redeem_all`] drains in passes —
//! redeem a page-set, re-fetch the now-smaller set, and repeat until it is
//! empty.
//!
//! Layers mirror [`crate::convert`]: the pure grouping ([`group_redeemable`],
//! [`build_redemptions`]) is always available; the live engine
//! ([`redeem_all`], [`plan_redeem`]) needs the `rpc` feature for the balance
//! reads.

use std::collections::HashMap;

use alloy::primitives::{B256, U256};

use crate::data::Position;

/// One resolved condition's held outcome tokens, grouped from redeemable
/// positions.
///
/// `yes_token` / `no_token` are the held ERC-1155 token ids (absent ⇒ that
/// side isn't held). `neg_risk` records which redeem path the condition takes:
/// the adapter (multi-outcome) or the CTF (binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemGroup {
    pub condition_id: B256,
    pub yes_token: Option<U256>,
    pub no_token: Option<U256>,
    pub neg_risk: bool,
}

impl RedeemGroup {
    /// The held token ids in this group (for the balance read).
    fn token_ids(&self) -> impl Iterator<Item = U256> {
        self.yes_token.into_iter().chain(self.no_token)
    }
}

/// One condition ready to redeem: the held YES/NO amounts (raw 6-dp) and which
/// redeem path it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redemption {
    pub condition_id: B256,
    pub yes_amount: U256,
    pub no_amount: U256,
    pub neg_risk: bool,
}

fn parse_b256(s: &str) -> Option<B256> {
    s.strip_prefix("0x").unwrap_or(s).parse().ok()
}

/// Group redeemable positions by condition id, extracting the held YES/NO
/// token ids and tagging each condition's redeem path.
///
/// Rows with an unparseable condition id or token id are dropped; first-seen
/// condition order is preserved.
#[must_use]
pub fn group_redeemable(positions: &[Position]) -> Vec<RedeemGroup> {
    let mut order: Vec<B256> = Vec::new();
    let mut by_cond: HashMap<B256, RedeemGroup> = HashMap::new();
    for p in positions {
        let (Some(cid), Ok(asset)) = (parse_b256(&p.condition_id), p.asset.parse::<U256>()) else {
            continue;
        };
        let group = by_cond.entry(cid).or_insert_with(|| {
            order.push(cid);
            RedeemGroup {
                condition_id: cid,
                yes_token: None,
                no_token: None,
                neg_risk: p.negative_risk,
            }
        });
        if p.outcome.eq_ignore_ascii_case("yes") {
            group.yes_token = Some(asset);
        } else if p.outcome.eq_ignore_ascii_case("no") {
            group.no_token = Some(asset);
        }
    }
    order
        .into_iter()
        .filter_map(|cid| by_cond.remove(&cid))
        .collect()
}

/// Pair grouped positions with their on-chain balances into [`Redemption`]s.
///
/// `balances` is keyed by token id (as read from `balanceOfBatch`). A
/// condition that nets to zero on-chain (a redeemed-but-lagging API row) or
/// holds less than `min_raw` (raw 6-dp) in total is dropped.
#[must_use]
pub fn build_redemptions<S: std::hash::BuildHasher>(
    groups: &[RedeemGroup],
    balances: &HashMap<U256, U256, S>,
    min_raw: U256,
) -> Vec<Redemption> {
    let held = |token: Option<U256>| {
        token
            .and_then(|t| balances.get(&t).copied())
            .unwrap_or(U256::ZERO)
    };
    groups
        .iter()
        .filter_map(|g| {
            let (yes, no) = (held(g.yes_token), held(g.no_token));
            let total = yes.saturating_add(no);
            (!total.is_zero() && total >= min_raw).then_some(Redemption {
                condition_id: g.condition_id,
                yes_amount: yes,
                no_amount: no,
                neg_risk: g.neg_risk,
            })
        })
        .collect()
}

#[cfg(feature = "rpc")]
pub use engine::{RedeemOptions, RedeemSummary, plan_redeem, redeem_all};

#[cfg(feature = "rpc")]
mod engine {
    use std::collections::HashMap;
    use std::time::Duration;

    use alloy::primitives::{Address, U256};
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::signers::Signer;

    use super::{RedeemGroup, Redemption, build_redemptions, group_redeemable};
    use crate::chain::{CTF, NEG_RISK_ADAPTER, POLYGON, contract_config};
    use crate::convert::{
        build_redeem_calldata, build_redeem_calldata_ctf, submit_and_settle_with_busy_retry,
    };
    use crate::data::{DataApiClient, Position};
    use crate::error::Error;
    use crate::relayer::{DepositWalletCall, RelayerClient};

    mod ifaces {
        #![allow(clippy::exhaustive_structs, reason = "Generated by sol! macro")]
        use alloy::sol;

        sol! {
            #[sol(rpc)]
            interface IERC1155 {
                function balanceOfBatch(address[] accounts, uint256[] ids) external view returns (uint256[]);
            }
        }
    }
    use ifaces::IERC1155;

    /// How many token balances to read per `balanceOfBatch` `eth_call`.
    const BALANCE_READ_CHUNK: usize = 500;

    /// Knobs for [`redeem_all`]. [`Default`] is a workable starting point;
    /// adjust to your relayer quota.
    #[derive(Debug, Clone, Copy)]
    pub struct RedeemOptions {
        /// Skip a condition whose total held (yes+no, raw 6-dp) is below this.
        pub min_shares_raw: U256,
        /// `DepositWallet` calls (one per condition) per relayer submission.
        pub batch_size: usize,
        /// Stop after this many conditions across the whole call (`0` = no cap).
        pub max_conditions: usize,
        /// Wait for on-chain settlement after each submission.
        pub settle: Duration,
        /// Retries while the relayer reports the wallet busy.
        pub wallet_busy_max_retries: u32,
        /// Whole-batch resubmits on a transient relayer/RPC failure before the
        /// batch is skipped (counted failed), so one wedged batch can't stall
        /// the drain.
        pub batch_max_retries: u32,
        /// Collateral token a binary condition pays out in (the token it was
        /// prepared with). `None` uses the venue default. A wrong value is a
        /// fail-safe no-op — the redeem finds no matching balance — so override
        /// it for markets collateralized in a different token.
        pub ctf_collateral: Option<Address>,
    }

    impl Default for RedeemOptions {
        fn default() -> Self {
            Self {
                min_shares_raw: U256::ZERO,
                batch_size: 20,
                max_conditions: 0,
                settle: Duration::from_secs(5),
                wallet_busy_max_retries: 10,
                batch_max_retries: 5,
                ctf_collateral: None,
            }
        }
    }

    /// What [`redeem_all`] did.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct RedeemSummary {
        /// Conditions redeemed (submitted successfully).
        pub redeemed: usize,
        /// Conditions whose batch failed after retries and was skipped.
        pub failed: usize,
        /// Drain passes run.
        pub passes: u32,
    }

    /// The venue's default collateral token (what current markets pay out in).
    fn venue_collateral() -> Address {
        contract_config(POLYGON, false).map_or(Address::ZERO, |c| c.collateral)
    }

    /// Build the relayer calls for a set of redemptions, routing each to the
    /// adapter or the CTF by its redeem path.
    fn build_calls(redemptions: &[Redemption], ctf_collateral: Address) -> Vec<DepositWalletCall> {
        // Both outcome slots of a binary condition; the CTF redeems whatever
        // balance is held of each.
        let binary_index_sets = [U256::from(1_u8), U256::from(2_u8)];
        redemptions
            .iter()
            .map(|r| {
                if r.neg_risk {
                    DepositWalletCall {
                        target: NEG_RISK_ADAPTER,
                        data: build_redeem_calldata(&r.condition_id, r.yes_amount, r.no_amount),
                    }
                } else {
                    DepositWalletCall {
                        target: CTF,
                        data: build_redeem_calldata_ctf(
                            ctf_collateral,
                            &r.condition_id,
                            &binary_index_sets,
                        ),
                    }
                }
            })
            .collect()
    }

    /// Read `balanceOf` for every token id, chunked into bounded
    /// `balanceOfBatch` calls.
    async fn read_balances<P: Provider>(
        ctf: &IERC1155::IERC1155Instance<P>,
        wallet: Address,
        ids: &[U256],
    ) -> Result<HashMap<U256, U256>, Error> {
        let mut out = HashMap::with_capacity(ids.len());
        for chunk in ids.chunks(BALANCE_READ_CHUNK) {
            let balances = ctf
                .balanceOfBatch(vec![wallet; chunk.len()], chunk.to_vec())
                .call()
                .await
                .map_err(|e| Error::InvalidData(format!("balanceOfBatch failed: {e}")))?;
            for (id, bal) in chunk.iter().zip(balances) {
                out.insert(*id, bal);
            }
        }
        Ok(out)
    }

    /// Group `positions`, read their exact on-chain balances, and build the
    /// redemptions — the read half shared by [`plan_redeem`] and
    /// [`redeem_all`].
    async fn read_and_plan<P: Provider>(
        positions: &[Position],
        ctf: &IERC1155::IERC1155Instance<P>,
        wallet: Address,
        min_raw: U256,
    ) -> Result<Vec<Redemption>, Error> {
        let groups = group_redeemable(positions);
        let ids: Vec<U256> = groups.iter().flat_map(RedeemGroup::token_ids).collect();
        let balances = read_balances(ctf, wallet, &ids).await?;
        Ok(build_redemptions(&groups, &balances, min_raw))
    }

    async fn connect_ctf(
        rpc_url: &str,
    ) -> Result<IERC1155::IERC1155Instance<impl Provider>, Error> {
        let provider = ProviderBuilder::new()
            .connect(rpc_url)
            .await
            .map_err(|e| Error::InvalidData(format!("RPC connect failed: {e}")))?;
        Ok(IERC1155::new(CTF, provider))
    }

    /// Preview one page-set: the redemptions [`redeem_all`] would submit,
    /// without submitting anything.
    ///
    /// Fetches one page-set of redeemable positions and reads their balances.
    /// `hit_cap` is `true` when more redeemable positions remain beyond the
    /// Data API's offset cap (a full [`redeem_all`] run drains them across
    /// passes).
    pub async fn plan_redeem(
        data: &DataApiClient,
        rpc_url: &str,
        wallet: Address,
        min_shares_raw: U256,
    ) -> Result<(Vec<Redemption>, bool), Error> {
        let (positions, hit_cap) = data.all_redeemable_positions(&wallet.to_string()).await?;
        let ctf = connect_ctf(rpc_url).await?;
        let redemptions = read_and_plan(&positions, &ctf, wallet, min_shares_raw).await?;
        Ok((redemptions, hit_cap))
    }

    /// Redeem every resolved position `wallet` holds, draining the redeemable
    /// set to empty (or until `max_conditions`).
    ///
    /// Each pass fetches one page-set of redeemable positions
    /// ([`DataApiClient::all_redeemable_positions`]), reads their exact
    /// balances, submits the redeems in `batch_size` chunks, then re-fetches
    /// the now-smaller set. It stops when the set is empty, a pass makes no
    /// progress (every batch failed), or the cap is reached. Idempotent and
    /// resumable — safe to re-run.
    ///
    /// Assumes the wallet's approvals are already in place: the adapter must be
    /// an ERC-1155 operator for the wallet so it can pull the multi-outcome
    /// tokens (see [`crate::approval`]); the CTF redeem burns the wallet's own
    /// tokens and needs no approval.
    pub async fn redeem_all<S: Signer + Sync>(
        signer: &S,
        relayer: &RelayerClient,
        data: &DataApiClient,
        rpc_url: &str,
        wallet: Address,
        opts: &RedeemOptions,
    ) -> Result<RedeemSummary, Error> {
        let ctf = connect_ctf(rpc_url).await?;
        let collateral = opts.ctf_collateral.unwrap_or_else(venue_collateral);
        let user = wallet.to_string();

        let mut summary = RedeemSummary::default();
        loop {
            summary.passes += 1;
            let (positions, hit_cap) = data.all_redeemable_positions(&user).await?;
            if positions.is_empty() {
                break;
            }
            let mut redemptions =
                read_and_plan(&positions, &ctf, wallet, opts.min_shares_raw).await?;
            if redemptions.is_empty() {
                break;
            }
            if opts.max_conditions > 0 {
                let remaining = opts
                    .max_conditions
                    .saturating_sub(summary.redeemed + summary.failed);
                if remaining == 0 {
                    break;
                }
                redemptions.truncate(remaining);
            }

            let calls = build_calls(&redemptions, collateral);
            let (ok, bad) = submit_batches(signer, relayer, wallet, &calls, opts).await;
            summary.redeemed += ok;
            summary.failed += bad;
            tracing::info!(pass = summary.passes, ok, bad, "redeem pass complete");

            if opts.max_conditions > 0 && summary.redeemed + summary.failed >= opts.max_conditions {
                break;
            }
            if ok == 0 {
                break; // no progress — the remaining conditions keep failing
            }
            if !hit_cap {
                break; // the redeemable set is fully drained
            }
        }
        Ok(summary)
    }

    /// Submit redeem calls in serial `batch_size` chunks (the wallet runs one
    /// relayer action at a time), retrying a failed batch whole up to
    /// `batch_max_retries` before skipping it. Returns `(redeemed, failed)`
    /// condition counts (one call = one condition).
    async fn submit_batches<S: Signer + Sync>(
        signer: &S,
        relayer: &RelayerClient,
        wallet: Address,
        calls: &[DepositWalletCall],
        opts: &RedeemOptions,
    ) -> (usize, usize) {
        let (mut ok, mut bad) = (0_usize, 0_usize);
        for chunk in calls.chunks(opts.batch_size.max(1)) {
            let mut attempt = 0;
            let result = loop {
                match submit_and_settle_with_busy_retry(
                    signer,
                    relayer,
                    wallet,
                    chunk,
                    "redeem",
                    opts.settle,
                    opts.wallet_busy_max_retries,
                )
                .await
                {
                    Ok(tx) => break Ok(tx),
                    Err(e) if attempt < opts.batch_max_retries => {
                        attempt += 1;
                        tracing::warn!(error = %e, attempt, "redeem batch failed; retrying whole batch");
                        tokio::time::sleep(opts.settle).await;
                    }
                    Err(e) => break Err(e),
                }
            };
            match result {
                Ok(_) => ok += chunk.len(),
                Err(e) => {
                    tracing::warn!(error = %e, batch = chunk.len(), "redeem batch skipped after retries");
                    bad += chunk.len();
                }
            }
        }
        (ok, bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-byte condition id tagged with `n`, as `(B256, "0x…" string)`.
    fn cid(n: u8) -> (B256, String) {
        let mut bytes = [0_u8; 32];
        bytes[31] = n;
        let value = B256::from(bytes);
        (value, value.to_string())
    }

    fn pos(asset: &str, condition_id: &str, outcome: &str, negative_risk: bool) -> Position {
        Position {
            asset: asset.to_owned(),
            size: 0.0,
            condition_id: condition_id.to_owned(),
            event_slug: String::new(),
            title: String::new(),
            outcome: outcome.to_owned(),
            negative_risk,
            redeemable: true,
        }
    }

    #[test]
    fn groups_both_market_types_and_tags_the_path() {
        let (multi_cid, multi_s) = cid(1);
        let (binary_cid, binary_s) = cid(2);
        let groups = group_redeemable(&[
            pos("100", &multi_s, "Yes", true),
            pos("200", &multi_s, "No", true),
            pos("300", &binary_s, "Yes", false),
        ]);
        assert_eq!(groups.len(), 2);
        // Multi-outcome condition (both sides held) → adapter path.
        assert_eq!(groups[0].condition_id, multi_cid);
        assert!(groups[0].neg_risk);
        assert_eq!(groups[0].yes_token, Some(U256::from(100_u64)));
        assert_eq!(groups[0].no_token, Some(U256::from(200_u64)));
        // Binary condition → kept (no longer dropped), CTF path.
        assert_eq!(groups[1].condition_id, binary_cid);
        assert!(!groups[1].neg_risk);
        assert_eq!(groups[1].yes_token, Some(U256::from(300_u64)));
    }

    #[test]
    fn drops_unparseable_rows() {
        let (_, cid_s) = cid(1);
        let groups = group_redeemable(&[
            pos("xyz", &cid_s, "No", true),       // unparseable token id
            pos("300", "0xnothex", "Yes", false), // unparseable condition id
        ]);
        assert!(groups.is_empty());
    }

    #[test]
    fn redemptions_skip_zero_balance_and_dust() {
        let (cid0, cid0s) = cid(1);
        let cid1s = cid(2).1;
        let cid2s = cid(3).1;
        let groups = group_redeemable(&[
            pos("10", &cid0s, "No", false), // binary, held above the floor → kept
            pos("20", &cid1s, "No", true),  // zero on-chain → dropped
            pos("30", &cid2s, "No", true),  // below the floor → dropped
        ]);
        let balances = HashMap::from([
            (U256::from(10_u64), U256::from(1_000_000_u64)),
            (U256::from(20_u64), U256::ZERO),
            (U256::from(30_u64), U256::from(100_u64)),
        ]);
        let redemptions = build_redemptions(&groups, &balances, U256::from(1_000_u64));
        assert_eq!(
            redemptions,
            vec![Redemption {
                condition_id: cid0,
                yes_amount: U256::ZERO,
                no_amount: U256::from(1_000_000_u64),
                neg_risk: false,
            }]
        );
    }
}
