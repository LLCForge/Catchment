//! Renderers: terminal table, JSON, CSV (formula-injection safe) and a static
//! HTML report (every value escaped, scripts pinned by CSP hashes).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use base64::Engine;
use serde::Serialize;

use crate::aggregate::{self, Comparison};
use crate::model::{family, Record, Report, Round, UNATTRIBUTED};
use crate::pathology;

/// Bundled map assets (d3-array, d3-geo, topojson-client, world-atlas 110m;
/// ISC licensed, see assets/map/LICENSES.txt). Embedded so the report works
/// offline and loads nothing from a CDN.
const D3_ARRAY: &str = include_str!("../assets/map/d3-array.min.js");
const D3_GEO: &str = include_str!("../assets/map/d3-geo.min.js");
const TOPOJSON: &str = include_str!("../assets/map/topojson-client.min.js");
const WORLD: &str = include_str!("../assets/map/countries-110m.json");
const MAP_JS: &str = include_str!("map.js");

/// Rows shown per table in terminal output before eliding.
const TABLE_ROWS: usize = 20;

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref().map(T::to_string).unwrap_or_else(|| "-".into())
}

fn ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}")).unwrap_or_else(|| "-".into())
}

fn is_dual(round: &Round) -> bool {
    let fams: BTreeSet<&str> = round
        .records
        .iter()
        .map(|r| family(r.target_or(round.target)))
        .collect();
    fams.len() > 1
}

/// Per-vantage table: fixed columns plus NSID / HTTP when any record has one.
fn vantage_table(round: &Round) -> (Vec<&'static str>, Vec<Vec<String>>) {
    let dual = is_dual(round);
    let nsid = round.records.iter().any(|r| r.obs.nsid.is_some());
    let http = round.records.iter().any(|r| r.obs.http_id.is_some());
    let mut headers = vec!["VANTAGE", "CC", "ASN", "POP", "MATCH", "CHAOS"];
    if nsid {
        headers.push("NSID");
    }
    if http {
        headers.push("HTTP");
    }
    headers.extend(["LAST HOP", "RTT MS", "ERROR"]);
    let rows = round
        .records
        .iter()
        .map(|r: &Record| {
            let mut vantage = r.obs.vantage.clone();
            if dual {
                let _ = write!(vantage, " ({})", family(r.target_or(round.target)));
            }
            let mut row = vec![
                vantage,
                opt(&r.obs.country),
                opt(&r.obs.asn),
                r.pop_label().to_string(),
                r.matched_by
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| "-".into()),
                opt(&r.obs.chaos),
            ];
            if nsid {
                row.push(opt(&r.obs.nsid));
            }
            if http {
                row.push(opt(&r.obs.http_id));
            }
            row.extend([opt(&r.obs.last_hop), ms(r.obs.rtt_ms), opt(&r.obs.error)]);
            row
        })
        .collect();
    (headers, rows)
}

/// PoP -> (vantage count, countries).
fn summary(round: &Round) -> BTreeMap<String, (usize, BTreeSet<String>)> {
    let mut out: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
    for r in &round.records {
        let e = out.entry(r.pop_label().to_string()).or_default();
        e.0 += 1;
        e.1.insert(opt(&r.obs.country));
    }
    out
}

fn summary_rows(round: &Round, sep: &str) -> Vec<Vec<String>> {
    summary(round)
        .into_iter()
        .map(|(pop, (n, cc))| {
            vec![
                pop,
                n.to_string(),
                cc.into_iter().collect::<Vec<_>>().join(sep),
            ]
        })
        .collect()
}

fn asn_rows(round: &Round) -> Vec<Vec<String>> {
    aggregate::per_asn(round)
        .into_iter()
        .map(|a| {
            vec![
                a.asn
                    .map(|n| format!("AS{n}"))
                    .unwrap_or_else(|| "-".into()),
                a.vantages.to_string(),
                a.pops
                    .iter()
                    .map(|(p, n)| format!("{p}:{n}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ]
        })
        .collect()
}

fn table(out: &mut String, headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut line = |cells: Vec<&str>| {
        let mut l = String::new();
        for (i, (cell, w)) in cells.iter().zip(&widths).enumerate() {
            if i + 1 == cells.len() {
                l.push_str(cell);
            } else {
                let _ = write!(l, "{cell:<w$}  ");
            }
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(headers.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}

/// `table` with at most TABLE_ROWS rows and a hint about the rest.
fn table_capped(out: &mut String, headers: &[&str], rows: &[Vec<String>], what: &str) {
    table(out, headers, &rows[..rows.len().min(TABLE_ROWS)]);
    if rows.len() > TABLE_ROWS {
        let _ = writeln!(
            out,
            "... {} more {what} (use --format json)",
            rows.len() - TABLE_ROWS
        );
    }
}

pub fn render_table(report: &Report) -> String {
    let round = &report.round;
    let mut out = String::new();
    let mut head = format!(
        "Catchment round {}  target {}  vantages {}",
        round.started_rfc3339(),
        round.target,
        round.records.len()
    );
    if let Some(s) = &round.service {
        let _ = write!(head, "  service {s}");
    }
    if let Some(l) = &round.label {
        let _ = write!(head, "  label {l}");
    }
    let _ = writeln!(out, "{head}\n");
    let (headers, data) = vantage_table(round);
    table(&mut out, &headers, &data);

    out.push('\n');
    table(
        &mut out,
        &["POP", "VANTAGES", "COUNTRIES"],
        &summary_rows(round, ","),
    );

    let asns = asn_rows(round);
    if asns.len() > 1 {
        out.push('\n');
        table_capped(&mut out, &["ASN", "VANTAGES", "POPS"], &asns, "ASNs");
    }

    if let Some(d) = aggregate::dual_stack(round) {
        let _ = writeln!(
            out,
            "\nDual-stack: {} vantages, {} same PoP, {} different, median v6-v4 RTT {} ms",
            d.vantages,
            d.same_pop,
            d.different_pop,
            d.median_v6_minus_v4_ms
                .map(|v| format!("{v:+.1}"))
                .unwrap_or_else(|| "-".into())
        );
        if !d.mismatches.is_empty() {
            let rows: Vec<Vec<String>> = d
                .mismatches
                .iter()
                .map(|m| {
                    vec![
                        m.vantage.clone(),
                        opt(&m.country),
                        m.pop_v4.clone(),
                        m.pop_v6.clone(),
                        ms(m.rtt_v4_ms),
                        ms(m.rtt_v6_ms),
                    ]
                })
                .collect();
            table_capped(
                &mut out,
                &["VANTAGE", "CC", "POP V4", "POP V6", "RTT V4", "RTT V6"],
                &rows,
                "vantages",
            );
        }
    }

    out.push('\n');
    if report.previous_started_ms.is_none() {
        out.push_str("No previous round to compare against.\n");
    } else if report.shifts.is_empty() {
        out.push_str("No catchment shifts since the previous round.\n");
    } else {
        let _ = writeln!(out, "Catchment shifts: {}", report.shifts.len());
        let shifts: Vec<Vec<String>> = report
            .country_shifts
            .iter()
            .map(|c| {
                let cc = match (c.target, is_dual(round)) {
                    (Some(t), true) => format!("{} ({})", c.country, family(t)),
                    _ => c.country.clone(),
                };
                vec![
                    cc,
                    format!("{} -> {}", c.from, c.to),
                    c.vantages.to_string(),
                ]
            })
            .collect();
        table(&mut out, &["COUNTRY", "SHIFT", "VANTAGES"], &shifts);
    }
    if !report.latency_regressions.is_empty() {
        let _ = writeln!(
            out,
            "\nLatency regressions: {}",
            report.latency_regressions.len()
        );
        let rows: Vec<Vec<String>> = report
            .latency_regressions
            .iter()
            .map(|r| {
                vec![
                    r.country.clone(),
                    family(r.target).to_string(),
                    format!("{:.1}", r.baseline_ms),
                    format!("{:.1}", r.current_ms),
                    r.vantages.to_string(),
                ]
            })
            .collect();
        table(
            &mut out,
            &["COUNTRY", "AF", "BASELINE MS", "NOW MS", "VANTAGES"],
            &rows,
        );
    }
    if let Some(c) = &report.path_correlation {
        let _ = writeln!(out, "\nPathology: {} since {}", c.prefix, c.since);
        match &c.error {
            Some(e) => {
                let _ = writeln!(out, "  unavailable: {e}");
            }
            None if c.events.is_empty() => out.push_str("  no path changes seen\n"),
            None => {
                for e in c.events.iter().take(TABLE_ROWS) {
                    let _ = writeln!(out, "  {}", pathology::describe(e));
                }
            }
        }
    }
    out
}

#[derive(Serialize)]
struct JsonReport<'a> {
    #[serde(flatten)]
    report: &'a Report,
    per_asn: Vec<aggregate::AsnRow>,
    country_latency: Vec<aggregate::CountryLatency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dual_stack: Option<aggregate::DualStack>,
}

pub fn render_json(report: &Report) -> anyhow::Result<String> {
    let r = &report.round;
    let doc = JsonReport {
        report,
        per_asn: aggregate::per_asn(r),
        country_latency: aggregate::country_latency(r),
        dual_stack: aggregate::dual_stack(r),
    };
    Ok(serde_json::to_string_pretty(&doc)? + "\n")
}

/// RFC 4180 quoting plus a leading `'` on cells a spreadsheet would treat as a formula.
pub fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) && s != "-" {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn render_csv(report: &Report) -> String {
    let mut out = String::from(
        "started,vantage,country,asn,pop,matched_by,chaos,last_hop,last_hop_asn,last_hop_rdns,rtt_ms,error,target,nsid,http_id,lat,lon,service,label\n",
    );
    let round = &report.round;
    let started = round.started_rfc3339();
    let s = |v: &Option<String>| v.clone().unwrap_or_default();
    let n = |v: Option<f64>| v.map(|v| format!("{v:.3}")).unwrap_or_default();
    for r in &round.records {
        let cells = [
            started.clone(),
            r.obs.vantage.clone(),
            s(&r.obs.country),
            r.obs.asn.map(|a| a.to_string()).unwrap_or_default(),
            r.pop.clone().unwrap_or_else(|| UNATTRIBUTED.into()),
            r.matched_by
                .map(|m| m.as_str().to_string())
                .unwrap_or_default(),
            s(&r.obs.chaos),
            r.obs.last_hop.map(|a| a.to_string()).unwrap_or_default(),
            r.obs
                .last_hop_asn
                .map(|a| a.to_string())
                .unwrap_or_default(),
            s(&r.obs.last_hop_rdns),
            n(r.obs.rtt_ms),
            s(&r.obs.error),
            r.target_or(round.target).to_string(),
            s(&r.obs.nsid),
            s(&r.obs.http_id),
            n(r.obs.lat),
            n(r.obs.lon),
            s(&round.service),
            s(&round.label),
        ];
        let line: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// JSON safe to embed in a `<script type="application/json">` block.
pub fn json_for_script(v: &str) -> String {
    v.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn csp_hash(script: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, script.as_bytes());
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
    )
}

fn html_table(out: &mut String, headers: &[&str], rows: &[Vec<String>]) {
    out.push_str("<table><thead><tr>");
    for h in headers {
        let _ = write!(out, "<th>{}</th>", html_escape(h));
    }
    out.push_str("</tr></thead><tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            let _ = write!(out, "<td>{}</td>", html_escape(cell));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table>\n");
}

#[derive(Serialize)]
struct MapPoint<'a> {
    vantage: &'a str,
    pop: &'a str,
    country: Option<&'a str>,
    lat: f64,
    lon: f64,
    rtt: Option<f64>,
}

#[derive(Serialize)]
struct MapData<'a> {
    pops: Vec<String>,
    points: Vec<MapPoint<'a>>,
}

/// Vantages of the primary address that carry a location.
fn map_data(round: &Round) -> MapData<'_> {
    let points: Vec<MapPoint> = round
        .records
        .iter()
        .filter(|r| r.target_or(round.target) == round.target)
        .filter_map(|r| {
            Some(MapPoint {
                vantage: &r.obs.vantage,
                pop: r.pop_label(),
                country: r.obs.country.as_deref(),
                lat: r.obs.lat?,
                lon: r.obs.lon?,
                rtt: r.obs.rtt_ms,
            })
        })
        .collect();
    MapData {
        pops: summary(round).into_keys().collect(),
        points,
    }
}

/// Self-contained report: inline data and bundled libraries only; the CSP
/// allows exactly the embedded scripts (by SHA-256) and nothing remote.
pub fn render_html(report: &Report) -> String {
    let round = &report.round;
    let scripts = [D3_ARRAY, D3_GEO, TOPOJSON, MAP_JS];
    let hashes: Vec<String> = scripts.iter().map(|s| csp_hash(s)).collect();
    let mut out = String::new();
    let _ = write!(
        out,
        concat!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src {}\">",
            "<title>Catchment report</title><style>",
            "body{{font-family:system-ui,sans-serif;margin:24px;color:#1b1f24;background:#fff;line-height:1.5}}",
            "table{{border-collapse:collapse;margin:12px 0 28px}}",
            "th,td{{border-bottom:1px solid #d0d7de;padding:4px 10px;text-align:left;font-size:14px}}",
            "th{{background:#f3f5f7}}td{{font-family:ui-monospace,monospace}}",
            "#map{{width:100%;max-width:1100px;height:auto;display:block;background:#f3f5f7;border:1px solid #d0d7de}}",
            ".sphere{{fill:#eaf1f8}}.countries path{{fill:#d9dee4;stroke:#fff;stroke-width:.5}}",
            ".pt{{stroke:#1b1f24;stroke-width:.6}}#legend{{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:16px;font-size:14px}}",
            "#legend svg{{vertical-align:middle;margin-right:6px}}.muted{{color:#57606a;font-size:14px}}",
            "</style></head><body>\n"
        ),
        hashes.join(" ")
    );
    let mut sub = format!(
        "Round {} &middot; target {} &middot; {} vantages",
        html_escape(&round.started_rfc3339()),
        html_escape(&round.target.to_string()),
        round.records.len()
    );
    if let Some(s) = &round.service {
        let _ = write!(sub, " &middot; service {}", html_escape(s));
    }
    if let Some(l) = &round.label {
        let _ = write!(sub, " &middot; label {}", html_escape(l));
    }
    let _ = writeln!(out, "<h1>Catchment report</h1><p>{sub}</p>");

    let data = map_data(round);
    let located = data.points.len();
    out.push_str("<h2>Map</h2>\n<svg id=\"map\" viewBox=\"0 0 960 500\" role=\"img\" aria-label=\"World map of vantage points coloured by PoP\"></svg>\n<ul id=\"legend\"></ul>\n");
    let _ = writeln!(
        out,
        "<p class=\"muted\">{located} of {} vantages have a location (RIPE Atlas probe coordinates or configured lat/lon). Map data: Natural Earth via world-atlas; rendering: d3-geo.</p>",
        round.records.len()
    );

    out.push_str("<h2>PoPs</h2>\n");
    html_table(
        &mut out,
        &["PoP", "Vantages", "Countries"],
        &summary_rows(round, ", "),
    );
    out.push_str("<h2>Shifts since previous round</h2>\n");
    if report.shifts.is_empty() {
        out.push_str("<p>None.</p>\n");
    } else {
        let shifts: Vec<Vec<String>> = report
            .shifts
            .iter()
            .map(|s| {
                vec![
                    s.vantage.clone(),
                    s.target
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "-".into()),
                    opt(&s.country),
                    s.from.clone(),
                    s.to.clone(),
                ]
            })
            .collect();
        html_table(
            &mut out,
            &["Vantage", "Target", "Country", "From", "To"],
            &shifts,
        );
    }
    if !report.latency_regressions.is_empty() {
        out.push_str("<h2>Latency regressions</h2>\n");
        let rows: Vec<Vec<String>> = report
            .latency_regressions
            .iter()
            .map(|r| {
                vec![
                    r.country.clone(),
                    r.target.to_string(),
                    format!("{:.1}", r.baseline_ms),
                    format!("{:.1}", r.current_ms),
                    r.vantages.to_string(),
                ]
            })
            .collect();
        html_table(
            &mut out,
            &["Country", "Target", "Baseline ms", "Now ms", "Vantages"],
            &rows,
        );
    }
    if let Some(c) = &report.path_correlation {
        let _ = writeln!(
            out,
            "<h2>BGP path changes (Pathology)</h2><p>{} since {}</p>",
            html_escape(&c.prefix),
            html_escape(&c.since)
        );
        if let Some(e) = &c.error {
            let _ = writeln!(out, "<p>Unavailable: {}</p>", html_escape(e));
        } else {
            let rows: Vec<Vec<String>> = c
                .events
                .iter()
                .map(|e| vec![pathology::describe(e)])
                .collect();
            html_table(&mut out, &["Event"], &rows);
        }
    }
    out.push_str("<h2>Per ASN</h2>\n");
    html_table(&mut out, &["ASN", "Vantages", "PoPs"], &asn_rows(round));
    if let Some(d) = aggregate::dual_stack(round) {
        let _ = writeln!(
            out,
            "<h2>Dual-stack</h2><p>{} vantages measured both families: {} same PoP, {} different; median IPv6 minus IPv4 RTT {} ms.</p>",
            d.vantages,
            d.same_pop,
            d.different_pop,
            html_escape(&d.median_v6_minus_v4_ms.map(|v| format!("{v:+.1}")).unwrap_or_else(|| "-".into()))
        );
        let rows: Vec<Vec<String>> = d
            .mismatches
            .iter()
            .map(|m| {
                vec![
                    m.vantage.clone(),
                    opt(&m.country),
                    m.pop_v4.clone(),
                    m.pop_v6.clone(),
                    ms(m.rtt_v4_ms),
                    ms(m.rtt_v6_ms),
                ]
            })
            .collect();
        if !rows.is_empty() {
            html_table(
                &mut out,
                &["Vantage", "Country", "PoP v4", "PoP v6", "RTT v4", "RTT v6"],
                &rows,
            );
        }
    }
    out.push_str("<h2>Vantages</h2>\n");
    let (headers, data_rows) = vantage_table(round);
    html_table(&mut out, &headers, &data_rows);

    let json =
        serde_json::to_string(&data).unwrap_or_else(|_| "{\"pops\":[],\"points\":[]}".into());
    let _ = writeln!(
        out,
        "<script type=\"application/json\" id=\"catchment-data\">{}</script>",
        json_for_script(&json)
    );
    let _ = writeln!(
        out,
        "<script type=\"application/json\" id=\"catchment-world\">{}</script>",
        json_for_script(WORLD.trim())
    );
    for s in scripts {
        let _ = writeln!(out, "<script>{s}</script>");
    }
    out.push_str("</body></html>\n");
    out
}

pub fn render_compare_table(c: &Comparison) -> String {
    let mut out = String::new();
    let r = |r: &aggregate::RoundRef| {
        format!(
            "{}  label {}  vantages {}",
            r.started,
            r.label.as_deref().unwrap_or("-"),
            r.vantages
        )
    };
    let _ = writeln!(out, "Catchment compare  service {}", c.service);
    let _ = writeln!(out, "before  {}", r(&c.before));
    let _ = writeln!(out, "after   {}\n", r(&c.after));
    let pops: Vec<Vec<String>> = c
        .pops
        .iter()
        .map(|p| {
            vec![
                p.pop.clone(),
                p.family.to_string(),
                p.before.to_string(),
                p.after.to_string(),
                format!("{:+}", p.after as i64 - p.before as i64),
            ]
        })
        .collect();
    table(&mut out, &["POP", "AF", "BEFORE", "AFTER", "DELTA"], &pops);
    out.push('\n');
    if c.moved.is_empty() {
        out.push_str("No vantage moved.\n");
    } else {
        let rows: Vec<Vec<String>> = c
            .moved
            .iter()
            .map(|m| {
                vec![
                    m.vantage.clone(),
                    opt(&m.country),
                    format!("{} -> {}", m.from, m.to),
                ]
            })
            .collect();
        table_capped(&mut out, &["MOVED", "CC", "SHIFT"], &rows, "vantages");
    }
    if !c.latency.is_empty() {
        out.push('\n');
        let rows: Vec<Vec<String>> = c
            .latency
            .iter()
            .map(|l| {
                let delta = match (l.before_ms, l.after_ms) {
                    (Some(b), Some(a)) => format!("{:+.1}", a - b),
                    _ => "-".into(),
                };
                vec![
                    l.country.clone(),
                    l.family.to_string(),
                    ms(l.before_ms),
                    ms(l.after_ms),
                    delta,
                ]
            })
            .collect();
        table_capped(
            &mut out,
            &["COUNTRY", "AF", "BEFORE MS", "AFTER MS", "DELTA"],
            &rows,
            "countries",
        );
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{CatchmentShift, CountryShift, MatchKind, Observation};

    pub(crate) fn sample_report() -> Report {
        let rec = |v: &str,
                   cc: &str,
                   asn: u32,
                   pop: Option<&str>,
                   chaos: Option<&str>,
                   hop: Option<&str>,
                   rtt: Option<f64>| Record {
            obs: Observation {
                vantage: v.into(),
                country: Some(cc.into()),
                asn: Some(asn),
                chaos: chaos.map(Into::into),
                last_hop: hop.map(|h| h.parse().unwrap()),
                rtt_ms: rtt,
                ..Observation::default()
            },
            matched_by: pop.map(|_| {
                if chaos.is_some() {
                    MatchKind::Chaos
                } else {
                    MatchKind::LastHopPrefix
                }
            }),
            pop: pop.map(Into::into),
        };
        let target = "192.0.2.53".parse().unwrap();
        Report {
            round: Round {
                started_ms: 1_767_225_600_000,
                target,
                service: None,
                label: None,
                records: vec![
                    rec(
                        "atlas:1001",
                        "DE",
                        64496,
                        Some("fra1"),
                        Some("fra1.example"),
                        Some("198.51.100.1"),
                        Some(12.5),
                    ),
                    rec(
                        "atlas:1002",
                        "DE",
                        64497,
                        Some("ist1"),
                        Some("ist1-01.example"),
                        None,
                        Some(41.2),
                    ),
                    rec(
                        "atlas:1003",
                        "US",
                        64500,
                        Some("nyc1"),
                        None,
                        Some("198.51.100.77"),
                        Some(88.0),
                    ),
                    rec(
                        "atlas:1004",
                        "BR",
                        64501,
                        None,
                        Some("=cmd|' /C calc'!A0"),
                        None,
                        None,
                    ),
                    rec(
                        "local",
                        "TR",
                        64510,
                        Some("ist1"),
                        Some("ist1-02.example"),
                        None,
                        Some(8.3),
                    ),
                ],
            },
            previous_started_ms: Some(1_767_224_700_000),
            shifts: vec![CatchmentShift {
                vantage: "atlas:1002".into(),
                target: Some(target),
                country: Some("DE".into()),
                from: "fra1".into(),
                to: "ist1".into(),
            }],
            country_shifts: vec![CountryShift {
                country: "DE".into(),
                target: Some(target),
                from: "fra1".into(),
                to: "ist1".into(),
                vantages: 1,
            }],
            latency_regressions: Vec::new(),
            path_correlation: None,
        }
    }

    #[test]
    fn table_layout() {
        let t = render_table(&sample_report());
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(
            lines[0],
            "Catchment round 2026-01-01T00:00:00Z  target 192.0.2.53  vantages 5"
        );
        assert!(lines[2].starts_with("VANTAGE     CC  ASN    POP"));
        assert!(t.contains("unattributed"));
        assert!(t.contains("DE       fra1 -> ist1  1"));
        assert!(t.contains("AS64496  1         fra1:1"));
        assert!(!t.contains("NSID"), "NSID column only when present");
    }

    #[test]
    fn dual_stack_and_nsid_columns() {
        let mut r = sample_report();
        let mut v6 = r.round.records[0].clone();
        v6.obs.target = Some("2001:db8::53".parse().unwrap());
        v6.obs.nsid = Some("fra1-ns".into());
        v6.pop = Some("ams1".into());
        r.round.records.push(v6);
        let t = render_table(&r);
        assert!(t.contains("NSID"));
        assert!(t.contains("atlas:1001 (v6)"));
        assert!(t.contains("Dual-stack: 1 vantages, 0 same PoP, 1 different"));
        let json: serde_json::Value = serde_json::from_str(&render_json(&r).unwrap()).unwrap();
        assert_eq!(json["dual_stack"]["different_pop"], 1);
        assert!(json["per_asn"].as_array().unwrap().len() >= 5);
    }

    #[test]
    fn csv_escapes_formulas_and_quotes() {
        assert_eq!(csv_cell("=1+1"), "'=1+1");
        assert_eq!(csv_cell("+x"), "'+x");
        assert_eq!(csv_cell("-2"), "'-2");
        assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("fra1.example"), "fra1.example");
        let csv = render_csv(&sample_report());
        assert!(csv.contains(",'=cmd|' /C calc'!A0,"));
        assert_eq!(csv.lines().count(), 6);
        assert!(csv.lines().all(|l| l.split(',').count() >= 19));
    }

    #[test]
    fn html_escapes_untrusted_strings_and_pins_scripts() {
        let mut r = sample_report();
        r.round.records[0].obs.chaos = Some("<script>alert('x')</script>".into());
        r.round.records[0].obs.lat = Some(50.1);
        r.round.records[0].obs.lon = Some(8.7);
        r.round.records[0].obs.vantage = "</script><script>alert(1)</script>".into();
        let html = render_html(&r);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(html.contains("\\u003c/script\\u003e"));
        assert!(html.contains("Content-Security-Policy"));
        // Every inline executable script is allowed by exactly its hash.
        for s in [D3_ARRAY, D3_GEO, TOPOJSON, MAP_JS] {
            assert!(html.contains(&csp_hash(s)));
        }
        assert!(!html.contains("https://cdn"));
        assert!(html.contains("1 of 5 vantages have a location"));
    }

    #[test]
    fn json_roundtrips_round() {
        let r = sample_report();
        let v: serde_json::Value = serde_json::from_str(&render_json(&r).unwrap()).unwrap();
        let round: Round = serde_json::from_value(v["round"].clone()).unwrap();
        assert_eq!(round, r.round);
        assert_eq!(v["shifts"][0]["to"], "ist1");
        assert_eq!(v["country_latency"][0]["country"], "DE");
    }

    #[test]
    fn compare_table() {
        let before = sample_report().round;
        let mut after = before.clone();
        after.records[1].pop = Some("fra1".into());
        after.label = Some("after".into());
        let t = render_compare_table(&aggregate::compare(&before, &after));
        assert!(t.contains("MOVED       CC  SHIFT"));
        assert!(t.contains("atlas:1002  DE  ist1 -> fra1"));
        assert!(t.contains("fra1          v4  1       2      +1"));
    }
}
