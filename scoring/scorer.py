import yaml
import os

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "weights.yaml")

def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return yaml.safe_load(f)

def compute_score(header_analysis, body_analysis, attachment_analysis, enrichment):
    config = _load_config()
    thresholds = config.get("thresholds", {})
    score_map = config.get("scores", {})

    all_anomalies = []
    all_anomalies.extend(header_analysis.get("anomalies", []))
    all_anomalies.extend(body_analysis.get("anomalies", []))
    all_anomalies.extend(enrichment.get("anomalies", []))
    for att in attachment_analysis.get("attachments", []):
        all_anomalies.extend(att.get("anomalies", []))

    # Apply weights from config if present, otherwise use the hardcoded value in the anomaly
    for anomaly in all_anomalies:
        atype = anomaly.get("type")
        if atype in score_map:
            anomaly["score"] = score_map[atype]

    raw_score = sum(a.get("score", 0) for a in all_anomalies)
    final_score = min(raw_score, 100)

    t_suspicious = thresholds.get("suspicious", 30)
    t_likely = thresholds.get("likely_malicious", 60)

    if final_score == 0:
        verdict = "BENIGN"
    elif final_score < t_suspicious:
        verdict = "SUSPICIOUS"
    elif final_score < t_likely:
        verdict = "LIKELY_MALICIOUS"
    else:
        verdict = "MALICIOUS"

    color_map = {
        "BENIGN":           "#2ecc71",
        "SUSPICIOUS":       "#f39c12",
        "LIKELY_MALICIOUS": "#e67e22",
        "MALICIOUS":        "#e74c3c",
    }

    return {
        "score": final_score,
        "raw_score": raw_score,
        "verdict": verdict,
        "color": color_map[verdict],
        "anomalies": all_anomalies,
        "anomaly_count": len(all_anomalies),
    }
