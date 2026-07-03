//! Client for Polymarket's Data API (wallet positions).
//!
//! Only `/positions` is implemented — enough to discover which events a
//! wallet actually holds (so tooling can act on those instead of probing
//! every event on-chain) and which of its positions are redeemable.
//!
//! Wire numerics are `f64` on purpose: these fields describe holdings for
//! discovery and reporting, and never feed order math (which is
//! [`rust_decimal::Decimal`] end to end elsewhere in this crate).

use std::collections::HashSet;

use serde::Deserialize;

use crate::chain::DATA_API_HOST;
use crate::error::Error;

/// One open position from the `/positions` endpoint, reduced to the
/// load-bearing fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Position {
    /// ERC1155 position token id as a decimal string — matches a market's
    /// YES/NO token id.
    pub asset: String,
    /// Position size in shares.
    pub size: f64,
    #[serde(default)]
    pub condition_id: String,
    #[serde(default)]
    pub event_slug: String,
    #[serde(default)]
    pub title: String,
    /// `"Yes"` / `"No"` when the API includes it.
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub negative_risk: bool,
    /// Whether the position's market has resolved and the position can be
    /// redeemed (populated on `redeemable=true` queries).
    #[serde(default)]
    pub redeemable: bool,
}

/// Client for the Polymarket Data API.
pub struct DataApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl Default for DataApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DataApiClient {
    /// A client against the production Data API ([`DATA_API_HOST`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_host(DATA_API_HOST)
    }

    /// A client against a specific host (no trailing slash).
    #[must_use]
    pub fn with_host(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Fetch every open position for `user`, paging until the API runs out.
    ///
    /// `size_threshold` is the minimum position size to return (the API
    /// default is 1; pass 0 for everything).
    pub async fn all_positions(
        &self,
        user: &str,
        size_threshold: f64,
    ) -> Result<Vec<Position>, Error> {
        let mut out = Vec::new();
        let mut offset = 0_u32;
        loop {
            let page = self
                .positions_page(
                    user,
                    &[("sizeThreshold", size_threshold.to_string())],
                    offset,
                )
                .await?;
            let full = page.len() >= PAGE_LIMIT as usize;
            out.extend(page);
            if !full || offset >= MAX_OFFSET {
                break;
            }
            offset += PAGE_LIMIT;
        }
        Ok(out)
    }

    /// Fetch the user's redeemable positions (`redeemable=true`), deduped by
    /// token id.
    ///
    /// Returns `(positions, hit_cap)`: `hit_cap` is `true` when paging
    /// stopped at the offset cap (a tail may remain beyond it — redeem what
    /// was returned, then re-fetch), `false` on a short final page (the real
    /// end of the redeemable set).
    pub async fn all_redeemable_positions(
        &self,
        user: &str,
    ) -> Result<(Vec<Position>, bool), Error> {
        let mut out: Vec<Position> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut offset = 0_u32;
        let mut hit_cap = false;
        loop {
            let page = self
                .positions_page(user, &[("redeemable", "true".to_owned())], offset)
                .await?;
            let n = page.len();
            let mut added = 0_usize;
            for p in page {
                if seen.insert(p.asset.clone()) {
                    out.push(p);
                    added += 1;
                }
            }
            if n < PAGE_LIMIT as usize {
                break; // short page → the real end of the redeemable set
            }
            // Offset cap (or its recycle: a full page that adds nothing new)
            // → a tail may remain.
            if offset >= MAX_OFFSET || added == 0 {
                hit_cap = true;
                break;
            }
            offset += PAGE_LIMIT;
        }
        Ok((out, hit_cap))
    }

    async fn positions_page(
        &self,
        user: &str,
        extra: &[(&str, String)],
        offset: u32,
    ) -> Result<Vec<Position>, Error> {
        let url = format!("{}/positions", self.base_url);
        let mut query: Vec<(&str, String)> = vec![
            ("user", user.to_owned()),
            ("limit", PAGE_LIMIT.to_string()),
            ("offset", offset.to_string()),
        ];
        query.extend(extra.iter().cloned());

        let resp = self.http.get(&url).query(&query).send().await?;

        if resp.status().as_u16() == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            return Err(Error::RateLimit { retry_after });
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api {
                status,
                body: body.chars().take(300).collect(),
            });
        }

        Ok(resp.json().await?)
    }
}

const PAGE_LIMIT: u32 = 500;

/// The Data API hard-caps `offset` at 10,000: requests past it don't error
/// or return a short page — they *recycle*, re-serving the offset-10,000
/// page. Callers summing `size` per row would silently double-count, so
/// paging stops at the cap. A wallet with >10,500 positions has an
/// unreachable tail; the remedy is redeeming resolved positions (shrinking
/// the live set back under the cap so paging terminates on a partial page).
const MAX_OFFSET: u32 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)] // exact parse of an exactly-representable literal
    fn position_parses_venue_shape() {
        let p: Position = serde_json::from_str(
            r#"{
                "asset": "71321045679252212594626385532706912750332728571942532289631379312455583992563",
                "size": 12.5,
                "conditionId": "0xabc",
                "eventSlug": "some-event",
                "title": "Some Event",
                "outcome": "Yes",
                "negativeRisk": true,
                "redeemable": true,
                "curPrice": 0.997,
                "somethingNew": {"ignored": true}
            }"#,
        )
        .unwrap();
        assert_eq!(p.size, 12.5);
        assert_eq!(p.event_slug, "some-event");
        assert_eq!(p.outcome, "Yes");
        assert!(p.negative_risk && p.redeemable);
    }

    #[test]
    fn position_is_lenient_about_missing_fields() {
        let p: Position = serde_json::from_str(r#"{"asset": "123", "size": 5.0}"#).unwrap();
        assert_eq!(p.asset, "123");
        assert!(p.condition_id.is_empty());
        assert!(!p.redeemable);
    }
}
