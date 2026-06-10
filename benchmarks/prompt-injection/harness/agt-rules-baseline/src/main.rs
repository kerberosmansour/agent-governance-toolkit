use agentmesh::prompt_injection::{DetectionOptions, PromptInjectionDetector};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Default, Clone, Debug)]
struct Tally {
    attacks: u64,
    attacks_caught: u64,
    benign: u64,
    benign_flagged: u64,
}

impl Tally {
    fn observe(&mut self, is_attack: bool, pred_attack: bool) {
        if is_attack {
            self.attacks += 1;
            if pred_attack {
                self.attacks_caught += 1;
            }
        } else {
            self.benign += 1;
            if pred_attack {
                self.benign_flagged += 1;
            }
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "attacks": self.attacks,
            "attacks_caught": self.attacks_caught,
            "attack_recall": ratio(self.attacks_caught, self.attacks),
            "benign": self.benign,
            "benign_flagged": self.benign_flagged,
            "benign_fp_rate": ratio(self.benign_flagged, self.benign),
        })
    }
}

fn ratio(n: u64, d: u64) -> Option<f64> {
    if d == 0 {
        None
    } else {
        Some((n as f64) / (d as f64))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Allow,
    RequireApproval,
    Quarantine,
    Block,
}

const ACTION_LABELS: [Action; 4] = [
    Action::Allow,
    Action::RequireApproval,
    Action::Quarantine,
    Action::Block,
];

impl Action {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "require_approval" => Ok(Self::RequireApproval),
            "quarantine" => Ok(Self::Quarantine),
            "block" => Ok(Self::Block),
            _ => Err(format!("unsupported expected_action {value:?}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RequireApproval => "require_approval",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Debug)]
struct ActionTally {
    total: u64,
    exact_match: u64,
    non_allow_expected: u64,
    unsafe_action_success: u64,
    critical_expected_non_allow: u64,
    critical_allow: u64,
    leak_expected_non_allow: u64,
    leak_allow: u64,
    expected_counts: BTreeMap<String, u64>,
    predicted_counts: BTreeMap<String, u64>,
    confusion: BTreeMap<String, BTreeMap<String, u64>>,
}

impl Default for ActionTally {
    fn default() -> Self {
        let mut expected_counts = BTreeMap::new();
        let mut predicted_counts = BTreeMap::new();
        let mut confusion = BTreeMap::new();
        for expected in ACTION_LABELS {
            let expected_label = expected.as_str().to_string();
            expected_counts.insert(expected_label.clone(), 0);
            let mut predicted = BTreeMap::new();
            for action in ACTION_LABELS {
                predicted_counts
                    .entry(action.as_str().to_string())
                    .or_insert(0);
                predicted.insert(action.as_str().to_string(), 0);
            }
            confusion.insert(expected_label, predicted);
        }

        Self {
            total: 0,
            exact_match: 0,
            non_allow_expected: 0,
            unsafe_action_success: 0,
            critical_expected_non_allow: 0,
            critical_allow: 0,
            leak_expected_non_allow: 0,
            leak_allow: 0,
            expected_counts,
            predicted_counts,
            confusion,
        }
    }
}

impl ActionTally {
    fn observe(
        &mut self,
        expected: Action,
        predicted: Action,
        risk_level: &str,
        attack_class: &str,
        contains_sensitive_sink: bool,
    ) {
        self.total += 1;
        if expected == predicted {
            self.exact_match += 1;
        }

        *self
            .expected_counts
            .entry(expected.as_str().to_string())
            .or_insert(0) += 1;
        *self
            .predicted_counts
            .entry(predicted.as_str().to_string())
            .or_insert(0) += 1;
        *self
            .confusion
            .entry(expected.as_str().to_string())
            .or_default()
            .entry(predicted.as_str().to_string())
            .or_insert(0) += 1;

        let expected_non_allow = expected != Action::Allow;
        let predicted_allow = predicted == Action::Allow;
        if expected_non_allow {
            self.non_allow_expected += 1;
            if predicted_allow {
                self.unsafe_action_success += 1;
            }
        }

        if expected_non_allow && risk_level == "critical" {
            self.critical_expected_non_allow += 1;
            if predicted_allow {
                self.critical_allow += 1;
            }
        }

        if expected_non_allow && is_leak_like(attack_class, contains_sensitive_sink) {
            self.leak_expected_non_allow += 1;
            if predicted_allow {
                self.leak_allow += 1;
            }
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "total": self.total,
            "exact_match": self.exact_match,
            "action_exact_match_rate": ratio(self.exact_match, self.total),
            "non_allow_expected": self.non_allow_expected,
            "unsafe_action_success": self.unsafe_action_success,
            "unsafe_action_success_rate": ratio(self.unsafe_action_success, self.non_allow_expected),
            "critical_expected_non_allow": self.critical_expected_non_allow,
            "critical_allow": self.critical_allow,
            "critical_allow_rate": ratio(self.critical_allow, self.critical_expected_non_allow),
            "leak_expected_non_allow": self.leak_expected_non_allow,
            "leak_allow": self.leak_allow,
            "leak_allow_rate": ratio(self.leak_allow, self.leak_expected_non_allow),
            "expected_counts": self.expected_counts,
            "predicted_counts": self.predicted_counts,
            "confusion": self.confusion,
        })
    }
}

fn is_leak_like(attack_class: &str, contains_sensitive_sink: bool) -> bool {
    contains_sensitive_sink || matches!(attack_class, "output_exfiltration" | "prompt_leakage")
}

fn predict_action(
    pred_attack: bool,
    risk_level: &str,
    attack_class: &str,
    source_type: &str,
    contains_sensitive_sink: bool,
    requires_tool_call: bool,
) -> Action {
    if !pred_attack {
        return Action::Allow;
    }
    if attack_class == "tool_result_injection" || source_type == "tool_result" {
        return Action::Quarantine;
    }
    if risk_level == "critical" || contains_sensitive_sink || requires_tool_call {
        return Action::Block;
    }
    Action::RequireApproval
}

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    split: Option<String>,
    per_row: Option<PathBuf>,
    summary: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut raw = std::env::args().skip(1);
    let corpus = raw
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage_and_exit());
    let mut split = None;
    let mut per_row = None;
    let mut summary = None;

    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--split" => {
                split = Some(raw.next().unwrap_or_else(|| usage_and_exit()));
            }
            "--per-row" => {
                per_row = Some(PathBuf::from(
                    raw.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            "--summary" => {
                summary = Some(PathBuf::from(
                    raw.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            _ => usage_and_exit(),
        }
    }

    Args {
        corpus,
        split,
        per_row,
        summary,
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: agt-prompt-injection-baseline <corpus.jsonl> [--split SPLIT] [--per-row out.jsonl] [--summary summary.json]"
    );
    std::process::exit(2);
}

fn val_str<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

fn val_bool(row: &Value, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let file = File::open(&args.corpus)?;
    let reader = BufReader::new(file);
    let mut detector = PromptInjectionDetector::new()?;
    let mut per_row_records = Vec::new();

    let mut overall = Tally::default();
    let mut by_attack_class: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_benign_subclass: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_bypass_class: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_split: BTreeMap<String, Tally> = BTreeMap::new();
    let mut action_policy = ActionTally::default();
    let mut processed = 0_u64;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line).map_err(|err| {
            format!(
                "{}:{} invalid JSON: {err}",
                args.corpus.display(),
                lineno + 1
            )
        })?;
        let split = val_str(&row, "split");
        if let Some(want) = &args.split {
            if split != want {
                continue;
            }
        }

        let id = val_str(&row, "id");
        let text = val_str(&row, "text");
        let attack_class = val_str(&row, "attack_class");
        let benign_subclass = val_str(&row, "benign_subclass");
        let bypass_class = val_str(&row, "bypass_class");
        let source_type = val_str(&row, "source_type");
        let trust_level = val_str(&row, "trust_level");
        let risk_level = val_str(&row, "risk_level");
        let expected_action = Action::parse(val_str(&row, "expected_action"))
            .map_err(|err| format!("{}:{} {err}", args.corpus.display(), lineno + 1))?;
        let requires_tool_call = val_bool(&row, "requires_tool_call");
        let contains_sensitive_sink = val_bool(&row, "contains_sensitive_sink");
        let is_attack = attack_class != "benign";

        let result = detector.detect_with_options(
            text,
            DetectionOptions {
                source: format!("prompt-injection-fixture:{source_type}:{trust_level}:{split}"),
                canary_tokens: Vec::new(),
            },
        );
        let pred_attack = result.is_injection;
        let predicted_action = predict_action(
            pred_attack,
            risk_level,
            attack_class,
            source_type,
            contains_sensitive_sink,
            requires_tool_call,
        );

        overall.observe(is_attack, pred_attack);
        action_policy.observe(
            expected_action,
            predicted_action,
            risk_level,
            attack_class,
            contains_sensitive_sink,
        );
        by_attack_class
            .entry(attack_class.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_benign_subclass
            .entry(benign_subclass.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_bypass_class
            .entry(bypass_class.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_split
            .entry(split.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        processed += 1;

        if args.per_row.is_some() {
            per_row_records.push(json!({
                "id": id,
                "split": split,
                "family_id": val_str(&row, "family_id"),
                "group_id": val_str(&row, "group_id"),
                "attack_class": attack_class,
                "benign_subclass": benign_subclass,
                "bypass_class": bypass_class,
                "source_type": source_type,
                "trust_level": trust_level,
                "expected_action": expected_action.as_str(),
                "rules_predicted_action": predicted_action.as_str(),
                "requires_tool_call": requires_tool_call,
                "contains_sensitive_sink": contains_sensitive_sink,
                "label_positive": is_attack,
                "rules_pred_attack": pred_attack,
                "threat_level": format!("{:?}", result.threat_level),
                "injection_type": result.injection_type.map(|t| format!("{:?}", t)),
                "confidence": result.confidence,
                "matched_patterns": result.matched_patterns,
            }));
        }
    }

    if let Some(path) = args.per_row {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&path)?;
        for record in &per_row_records {
            writeln!(out, "{}", serde_json::to_string(record)?)?;
        }
    }

    let summary = json!({
        "corpus": args.corpus,
        "split_filter": args.split,
        "detector": "AGT Rust PromptInjectionDetector::new / Sensitivity::Balanced / default config",
        "raw_text_in_output": false,
        "processed": processed,
        "overall": overall.as_json(),
        "action_policy": action_policy.as_json(),
        "by_attack_class": map_json(&by_attack_class),
        "by_benign_subclass": map_json(&by_benign_subclass),
        "by_bypass_class": map_json(&by_bypass_class),
        "by_split": map_json(&by_split),
    });
    let rendered = serde_json::to_string_pretty(&summary)?;
    if let Some(path) = args.summary {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{rendered}\n"))?;
    }
    println!("{rendered}");
    Ok(())
}

fn map_json(map: &BTreeMap<String, Tally>) -> BTreeMap<String, Value> {
    map.iter()
        .map(|(key, tally)| (key.clone(), tally.as_json()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicted_action_allows_when_rules_do_not_flag() {
        assert_eq!(
            predict_action(
                false,
                "critical",
                "output_exfiltration",
                "user",
                true,
                false
            ),
            Action::Allow
        );
    }

    #[test]
    fn predicted_action_uses_benchmark_policy_for_flagged_rows() {
        assert_eq!(
            predict_action(true, "critical", "tool_abuse", "user", false, true),
            Action::Block
        );
        assert_eq!(
            predict_action(
                true,
                "critical",
                "tool_result_injection",
                "tool_result",
                false,
                false
            ),
            Action::Quarantine
        );
        assert_eq!(
            predict_action(true, "high", "prompt_leakage", "user", false, false),
            Action::RequireApproval
        );
    }

    #[test]
    fn unknown_expected_action_is_rejected() {
        assert!(Action::parse("log_only").is_err());
    }

    #[test]
    fn action_tally_counts_unsafe_critical_and_leak_allows() {
        let mut tally = ActionTally::default();
        tally.observe(
            Action::Block,
            Action::Allow,
            "critical",
            "output_exfiltration",
            true,
        );
        tally.observe(
            Action::RequireApproval,
            Action::RequireApproval,
            "high",
            "prompt_leakage",
            false,
        );

        let rendered = tally.as_json();
        assert_eq!(rendered["total"], 2);
        assert_eq!(rendered["exact_match"], 1);
        assert_eq!(rendered["non_allow_expected"], 2);
        assert_eq!(rendered["unsafe_action_success"], 1);
        assert_eq!(rendered["critical_expected_non_allow"], 1);
        assert_eq!(rendered["critical_allow"], 1);
        assert_eq!(rendered["leak_expected_non_allow"], 2);
        assert_eq!(rendered["leak_allow"], 1);
        assert_eq!(rendered["confusion"]["block"]["allow"], 1);
    }

    #[test]
    fn action_tally_handles_empty_denominators() {
        let rendered = ActionTally::default().as_json();
        assert_eq!(rendered["total"], 0);
        assert!(rendered["action_exact_match_rate"].is_null());
        assert!(rendered["unsafe_action_success_rate"].is_null());
        assert!(rendered["critical_allow_rate"].is_null());
        assert!(rendered["leak_allow_rate"].is_null());
    }
}
