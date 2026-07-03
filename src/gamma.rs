//! Client for Polymarket's Gamma API (event and market metadata).
//!
//! Two access patterns: keyset paging over the open-event universe
//! ([`GammaClient::fetch_keyset_page`]) and slug-targeted resolution
//! ([`GammaClient::fetch_events_by_slug`], e.g. to resolve exactly the
//! events a wallet holds positions in).
//!
//! Wire numerics are `f64` on purpose: Gamma serves floats, and these fields
//! (volumes, indicative prices, fee rates) inform discovery and display —
//! they never feed order math, which is [`rust_decimal::Decimal`] end to end
//! elsewhere in this crate.

use serde::Deserialize;

use crate::chain::GAMMA_HOST;
use crate::convert::MarketIds;
use crate::error::Error;

/// One page of `GET /events/keyset`.
#[derive(Debug, Deserialize)]
pub struct KeysetResponse {
    #[serde(default)]
    pub events: Vec<GammaEvent>,
    /// Pass back as `after_cursor`; `None` on the last page.
    pub next_cursor: Option<String>,
}

/// One Gamma event with its nested markets.
#[derive(Debug, Deserialize)]
pub struct GammaEvent {
    pub id: String,
    pub slug: String,
    pub title: String,
    #[serde(rename = "negRisk", default)]
    pub neg_risk: bool,
    pub volume24hr: Option<f64>,
    #[serde(rename = "volume1wk", default)]
    pub volume_1wk: Option<f64>,
    /// RFC3339. For tournament futures this is the resolution deadline, not
    /// a start.
    #[serde(rename = "endDate")]
    pub end_date: Option<String>,
    /// Top-level scheduled start (RFC3339). For individual sports games this
    /// is the kickoff instant; absent on most non-game events.
    #[serde(rename = "startTime")]
    pub start_time: Option<String>,
    /// Event-level open instant (RFC3339) — ~market-creation time, set on
    /// every event.
    #[serde(rename = "startDate")]
    pub start_date: Option<String>,
    /// Gamma category tags (e.g. `sports`, `esports`, `golf`).
    #[serde(default)]
    pub tags: Vec<GammaTag>,
    pub markets: Option<Vec<GammaMarket>>,
}

/// A Gamma category tag. Only `slug` is load-bearing; the rest of the tag
/// object (id, label, timestamps) is ignored.
#[derive(Debug, Deserialize)]
pub struct GammaTag {
    #[serde(default)]
    pub slug: String,
}

/// One market (leg) of a Gamma event.
#[derive(Debug, Deserialize)]
pub struct GammaMarket {
    pub active: Option<bool>,
    #[serde(rename = "bestBid")]
    pub best_bid: Option<f64>,
    #[serde(rename = "bestAsk")]
    pub best_ask: Option<f64>,
    /// The leg's display title within its event (e.g. an outcome name).
    #[serde(rename = "groupItemTitle")]
    pub group_item_title: Option<String>,
    #[serde(rename = "feeSchedule")]
    pub fee_schedule: Option<FeeSchedule>,
    /// `[YES, NO]` token ids. Gamma delivers this as a JSON-encoded *string*
    /// (`"[\"123\",\"456\"]"`); the custom deserializer unwraps it.
    #[serde(
        default,
        rename = "clobTokenIds",
        deserialize_with = "deserialize_string_array"
    )]
    pub clob_token_ids: Option<Vec<String>>,
    #[serde(rename = "orderPriceMinTickSize")]
    pub tick_size: Option<f64>,
    #[serde(default, rename = "secondsDelay")]
    pub seconds_delay: Option<u32>,
    /// Per-game sports market kind (e.g. `"moneyline"`, `"totals"`). Set
    /// only on individual games; absent on season-long futures and
    /// non-sports markets — its presence is what distinguishes a single game
    /// from a futures market under the same Sports tag.
    #[serde(default, rename = "sportsMarketType")]
    pub sports_market_type: Option<String>,
    #[serde(default, rename = "questionID")]
    pub question_id: Option<String>,
    #[serde(default, rename = "conditionId")]
    pub condition_id: Option<String>,
}

impl GammaMarket {
    /// The market's YES token id (`clobTokenIds[0]`).
    #[must_use]
    pub fn yes_token_id(&self) -> Option<&str> {
        self.clob_token_ids.as_ref()?.first().map(String::as_str)
    }

    /// The market's NO token id (`clobTokenIds[1]`).
    #[must_use]
    pub fn no_token_id(&self) -> Option<&str> {
        self.clob_token_ids.as_ref()?.get(1).map(String::as_str)
    }

    /// The market's on-chain identifiers in the shape
    /// [`crate::convert::convert_legs`] consumes. `None` when the market has
    /// no NO token id.
    #[must_use]
    pub fn market_ids(&self) -> Option<MarketIds<'_>> {
        Some(MarketIds {
            question_id: self.question_id.as_deref(),
            condition_id: self.condition_id.as_deref(),
            yes_token_id: self.yes_token_id(),
            no_token_id: self.no_token_id()?,
        })
    }
}

fn deserialize_string_array<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

/// A market's platform-fee parameters (see [`crate::fee::platform_fee`]).
#[derive(Debug, Deserialize)]
pub struct FeeSchedule {
    /// Gross taker fee rate.
    pub rate: Option<f64>,
    #[serde(rename = "rebateRate")]
    pub rebate_rate: Option<f64>,
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn url_encode_into(s: &str, out: &mut String) {
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
}

/// Client for the Gamma API.
pub struct GammaClient {
    http: reqwest::Client,
    base_url: String,
}

impl Default for GammaClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GammaClient {
    /// A client against the production Gamma API ([`GAMMA_HOST`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_host(GAMMA_HOST)
    }

    /// A client against a specific host (no trailing slash).
    #[must_use]
    pub fn with_host(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// One keyset page of open events (`GET /events/keyset`). Page through
    /// by feeding each response's `next_cursor` back as `cursor`;
    /// `tag_slug` optionally filters by category.
    pub async fn fetch_keyset_page(
        &self,
        cursor: Option<&str>,
        limit: u32,
        tag_slug: Option<&str>,
    ) -> Result<KeysetResponse, Error> {
        let mut url = format!("{}/events/keyset?limit={limit}&closed=false", self.base_url);
        if let Some(c) = cursor {
            url.push_str("&after_cursor=");
            url_encode_into(c, &mut url);
        }
        if let Some(tag) = tag_slug {
            url.push_str("&tag_slug=");
            url_encode_into(tag, &mut url);
        }

        self.get_json(&url).await
    }

    /// Fetch the event(s) matching `slug` (normally one), with their nested
    /// markets. Lets a caller resolve a specific event instead of paging the
    /// universe — e.g. resolving exactly the events a wallet holds.
    pub async fn fetch_events_by_slug(&self, slug: &str) -> Result<Vec<GammaEvent>, Error> {
        let mut url = format!("{}/events?slug=", self.base_url);
        url_encode_into(slug, &mut url);

        self.get_json(&url).await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, Error> {
        let resp = self.http.get(url).send().await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding_is_rfc3986_unreserved() {
        let mut out = String::new();
        url_encode_into("abc-DEF_1.2~", &mut out);
        assert_eq!(out, "abc-DEF_1.2~");

        let mut out = String::new();
        url_encode_into("a b/c?d=e", &mut out);
        assert_eq!(out, "a%20b%2Fc%3Fd%3De");
    }

    #[test]
    fn deserializes_real_gamma_event_shape() {
        // Guards the serde wiring (camelCase renames, the `tags` array, the
        // JSON-encoded `clobTokenIds` string, ignored extra fields) against
        // a payload shaped like Gamma's real responses.
        let json = r#"{
            "id": "622565", "slug": "2026-travelers-championship-winner",
            "title": "PGA Tour: Travelers Championship Winner",
            "negRisk": true,
            "volume24hr": 12345.6,
            "startTime": "2026-06-25T00:00:00Z",
            "startDate": "2026-06-22T16:29:54.669905Z",
            "endDate": "2026-06-28T00:00:00Z",
            "tags": [
                {"id": "1", "label": "Sports", "slug": "sports", "forceHide": true},
                {"id": "100219", "label": "Golf", "slug": "golf"}
            ],
            "markets": [
                {
                    "active": true,
                    "groupItemTitle": "Sam Burns",
                    "clobTokenIds": "[\"100\",\"200\"]",
                    "orderPriceMinTickSize": 0.001,
                    "questionID": "0xaa0edfa656a0e70bf8c63f09438cd70979fef8e31fcc62d80840b5a375a55401",
                    "conditionId": "0xbb0edfa656a0e70bf8c63f09438cd70979fef8e31fcc62d80840b5a375a55401",
                    "feeSchedule": {"rate": 0.05, "rebateRate": 0.2}
                },
                {"active": false, "groupItemTitle": "Withdrawn Player"}
            ]
        }"#;
        let event: GammaEvent = serde_json::from_str(json).expect("real Gamma shape deserializes");
        assert!(event.neg_risk);
        assert_eq!(event.start_time.as_deref(), Some("2026-06-25T00:00:00Z"));
        assert!(event.tags.iter().any(|t| t.slug == "sports"));

        let markets = event.markets.expect("markets present");
        let m = &markets[0];
        assert_eq!(m.yes_token_id(), Some("100"));
        assert_eq!(m.no_token_id(), Some("200"));
        assert_eq!(m.tick_size, Some(0.001));
        assert_eq!(m.fee_schedule.as_ref().and_then(|f| f.rate), Some(0.05));

        // The convert adapter carries the ids through.
        let ids = m.market_ids().expect("two token ids present");
        assert_eq!(ids.no_token_id, "200");
        assert_eq!(ids.yes_token_id, Some("100"));
        assert!(ids.question_id.is_some() && ids.condition_id.is_some());

        // A market with no token ids yields no MarketIds.
        assert!(markets[1].market_ids().is_none());
    }

    #[test]
    fn keyset_response_parses_with_and_without_cursor() {
        let page: KeysetResponse =
            serde_json::from_str(r#"{"events": [], "next_cursor": "MTA="}"#).unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("MTA="));

        let last: KeysetResponse = serde_json::from_str(r#"{"next_cursor": null}"#).unwrap();
        assert!(last.events.is_empty());
        assert!(last.next_cursor.is_none());
    }

    #[test]
    fn clob_token_ids_missing_or_null_is_none() {
        let m: GammaMarket = serde_json::from_str(r#"{"active": true}"#).unwrap();
        assert!(m.clob_token_ids.is_none());
        let m: GammaMarket =
            serde_json::from_str(r#"{"active": true, "clobTokenIds": null}"#).unwrap();
        assert!(m.clob_token_ids.is_none());
    }
}
