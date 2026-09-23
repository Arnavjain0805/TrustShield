import pandas as pd
import json
import os
import random
import time
from unittest.mock import patch
import matplotlib.pyplot as plt

# Import the actual project functions
import risk
from defense import evaluate_input_robustness

random.seed(42)

def generate_synthetic_data():
    """Generates a reproducible synthetic test dataset."""
    data = []
    
    # 1. Clean legitimate inputs (Expect ALLOW)
    for i in range(40):
        clean_ip = f"192.168.1.{random.randint(1, 250)}"
        data.append({
            "case_id": f"clean_{i}",
            "category": "clean",
            "username": f"user_clean_{i}",
            "ip": clean_ip,
            "device": "Windows PC",
            "browser": "Chrome",
            "hour": random.randint(9, 17),
            "mfa_enabled": 1,
            # Registered values match perfectly
            "reg_ip": clean_ip,
            "reg_device": "Windows PC",
            "reg_browser": "Chrome",
            "expected_label": "ALLOW"
        })
        
    # 2. Suspicious but technically plausible inputs (Expect MFA)
    for i in range(30):
        data.append({
            "case_id": f"suspicious_{i}",
            "category": "suspicious",
            "username": f"user_susp_{i}",
            "ip": f"10.0.0.{random.randint(1, 250)}",
            "device": "MacBook Pro      ", # Excessive whitespace
            "browser": "Fiiirefox", # Repeated chars
            "hour": random.randint(0, 23),
            "mfa_enabled": 1,
            "reg_ip": "10.0.0.1",
            "reg_device": "Windows PC",
            "reg_browser": "Chrome",
            "expected_label": "MFA"
        })

    # 3. Clearly invalid or malicious-style inputs (Expect BLOCK)
    malicious_payloads = [
        {"device": "<script>alert(1)</script>", "browser": "Chrome", "hour": 14, "ip": "192.168.1.1"},
        {"device": "Windows PC", "browser": "Chrome", "hour": 25, "ip": "192.168.1.1"}, # Invalid hour
        {"device": "Windows PC", "browser": "A"*200, "hour": 12, "ip": "192.168.1.1"}, # Too long
        {"device": "Windows PC", "browser": "Chrome", "hour": 12, "ip": "999.999.999.999"}, # Invalid IP
        {"device": "OR 1=1 --", "browser": "Chrome", "hour": 12, "ip": "192.168.1.1"}, # Injection
        {"device": "Windows PC", "browser": "%00", "hour": 12, "ip": "192.168.1.1"} # Null byte equivalent
    ]
    
    for i in range(30):
        payload = random.choice(malicious_payloads)
        data.append({
            "case_id": f"malicious_{i}",
            "category": "malicious",
            "username": f"user_mal_{i}",
            "ip": payload["ip"],
            "device": payload["device"],
            "browser": payload["browser"],
            "hour": payload["hour"],
            "mfa_enabled": 1,
            "reg_ip": "192.168.1.1",
            "reg_device": "Windows PC",
            "reg_browser": "Chrome",
            "expected_label": "BLOCK"
        })
        
    return pd.DataFrame(data)

def normalize_label(decision_string):
    """Normalize labels to ALLOW, MFA, or BLOCK."""
    if not decision_string:
        return "UNKNOWN"
    d = str(decision_string).upper()
    if "ALLOW WITH MFA" in d or "MFA" in d:
        return "MFA"
    if "BLOCK" in d:
        return "BLOCK"
    if "ALLOW" in d:
        return "ALLOW"
    return "UNKNOWN"

def evaluate():
    print("Starting Evaluation Harness...")
    df = generate_synthetic_data()
    
    results = []
    
    # Evaluate Baseline (Bypassing Defense Layer)
    for _, row in df.iterrows():
        start_time = time.time()
        
        # Patch evaluate_input_robustness to return ("ALLOW", False, []) -> completely bypasses defense
        with patch('risk.evaluate_input_robustness', return_value=("ALLOW", False, [])):
            b_score, b_dec, _ = risk.predict_login(
                row['username'], row['ip'], row['device'], row['browser'], row['hour'], row['mfa_enabled'],
                registered_ip=row['reg_ip'], registered_device=row['reg_device'], registered_browser=row['reg_browser']
            )
            
        b_time = (time.time() - start_time) * 1000
        
        # Evaluate Defended (Normal risk.py with defense layer)
        start_time = time.time()
        d_score, d_dec, d_reasons = risk.predict_login(
            row['username'], row['ip'], row['device'], row['browser'], row['hour'], row['mfa_enabled'],
            registered_ip=row['reg_ip'], registered_device=row['reg_device'], registered_browser=row['reg_browser']
        )
        d_time = (time.time() - start_time) * 1000
        
        # Capture raw defense output for recording
        def_sev, def_susp, def_reas = evaluate_input_robustness(row['ip'], row['device'], row['browser'], row['hour'])
        
        norm_b_dec = normalize_label(b_dec)
        norm_d_dec = normalize_label(d_dec)
        
        results.append({
            "case_id": row['case_id'],
            "category": row['category'],
            "expected_label": row['expected_label'],
            "baseline_decision": norm_b_dec,
            "baseline_risk_score": b_score,
            "defended_decision": norm_d_dec,
            "defended_risk_score": d_score,
            "defense_severity": def_sev,
            "is_suspicious": def_susp,
            "defense_reasons": "; ".join(def_reas),
            "baseline_correct": norm_b_dec == row['expected_label'],
            "defended_correct": norm_d_dec == row['expected_label'],
            "baseline_execution_time_ms": b_time,
            "defended_execution_time_ms": d_time
        })
        
    results_df = pd.DataFrame(results)
    
    # Calculate Metrics
    def calc_metrics(df, mode_prefix):
        total = len(df)
        
        # Exact decision accuracy: output label equals expected label
        exact_correct = df[f"{mode_prefix}_correct"].sum()
        exact_accuracy = exact_correct / total if total > 0 else 0
        
        # Safe-decision rate: clean cases must be ALLOW, attack cases must not be ALLOW
        clean_safe = df[(df["category"] == "clean") & (df[f"{mode_prefix}_decision"] == "ALLOW")]
        attack_safe = df[(df["category"].isin(["suspicious", "malicious"])) & (df[f"{mode_prefix}_decision"] != "ALLOW")]
        safe_decision_rate = (len(clean_safe) + len(attack_safe)) / total if total > 0 else 0
        
        attack_cases = df[df["category"].isin(["suspicious", "malicious"])]
        false_accepts = attack_cases[attack_cases[f"{mode_prefix}_decision"] == "ALLOW"]
        far = len(false_accepts) / len(attack_cases) if len(attack_cases) > 0 else 0
        
        legit_cases = df[df["category"] == "clean"]
        false_rejects = legit_cases[legit_cases[f"{mode_prefix}_decision"].isin(["MFA", "BLOCK"])]
        frr = len(false_rejects) / len(legit_cases) if len(legit_cases) > 0 else 0
        
        attack_detected = attack_cases[attack_cases[f"{mode_prefix}_decision"].isin(["MFA", "BLOCK"])]
        adr = len(attack_detected) / len(attack_cases) if len(attack_cases) > 0 else 0
        
        # ASR is attack cases incorrectly classified as ALLOW
        attack_success = attack_cases[attack_cases[f"{mode_prefix}_decision"] == "ALLOW"]
        asr = len(attack_success) / len(attack_cases) if len(attack_cases) > 0 else 0
        
        counts = df[f"{mode_prefix}_decision"].value_counts().to_dict()
        
        # Confusion matrix / decision counts
        matrix = {
            "clean": {"ALLOW": 0, "MFA": 0, "BLOCK": 0},
            "suspicious": {"ALLOW": 0, "MFA": 0, "BLOCK": 0},
            "malicious": {"ALLOW": 0, "MFA": 0, "BLOCK": 0}
        }
        for _, row in df.iterrows():
            cat = row["category"]
            dec = row[f"{mode_prefix}_decision"]
            if dec in matrix[cat]:
                matrix[cat][dec] += 1
        
        return {
            "exact_decision_accuracy": float(exact_accuracy),
            "safe_decision_rate": float(safe_decision_rate),
            "false_accept_rate": float(far),
            "false_reject_rate": float(frr),
            "attack_detection_rate": float(adr),
            "attack_success_rate": float(asr),
            "total_cases": int(total),
            "decision_counts": {
                "ALLOW": int(counts.get("ALLOW", 0)),
                "MFA": int(counts.get("MFA", 0)),
                "BLOCK": int(counts.get("BLOCK", 0))
            },
            "confusion_matrix": matrix
        }
        
    metrics = {
        "baseline": calc_metrics(results_df, "baseline"),
        "defended": calc_metrics(results_df, "defended")
    }
    
    # Save outputs
    out_dir = "evaluation_results_corrected"
    os.makedirs(out_dir, exist_ok=True)
    
    results_df.to_csv(f"{out_dir}/evaluation_cases.csv", index=False)
    with open(f"{out_dir}/evaluation_metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)
        
    def format_matrix(m):
        return (f"    - Clean      => ALLOW: {m['clean']['ALLOW']}, MFA: {m['clean']['MFA']}, BLOCK: {m['clean']['BLOCK']}\n"
                f"    - Suspicious => ALLOW: {m['suspicious']['ALLOW']}, MFA: {m['suspicious']['MFA']}, BLOCK: {m['suspicious']['BLOCK']}\n"
                f"    - Malicious  => ALLOW: {m['malicious']['ALLOW']}, MFA: {m['malicious']['MFA']}, BLOCK: {m['malicious']['BLOCK']}\n")

    summary_text = (
        "======================================\n"
        "      DEFENSE EVALUATION SUMMARY      \n"
        "======================================\n"
        f"Total Test Cases: {len(results_df)}\n"
        f" - Clean: {len(results_df[results_df['category'] == 'clean'])}\n"
        f" - Suspicious: {len(results_df[results_df['category'] == 'suspicious'])}\n"
        f" - Malicious: {len(results_df[results_df['category'] == 'malicious'])}\n\n"
        
        "--- BASELINE METRICS ---\n"
        f"Exact Decision Accuracy: {metrics['baseline']['exact_decision_accuracy']:.2%}\n"
        f"Safe-Decision Rate: {metrics['baseline']['safe_decision_rate']:.2%}\n"
        f"False Accept Rate (FAR): {metrics['baseline']['false_accept_rate']:.2%}\n"
        f"False Reject Rate (FRR): {metrics['baseline']['false_reject_rate']:.2%}\n"
        f"Attack Detection Rate (ADR): {metrics['baseline']['attack_detection_rate']:.2%}\n"
        f"Attack Success Rate (ASR): {metrics['baseline']['attack_success_rate']:.2%}\n"
        f"Decision Matrix:\n{format_matrix(metrics['baseline']['confusion_matrix'])}\n"
        
        "--- DEFENDED METRICS ---\n"
        f"Exact Decision Accuracy: {metrics['defended']['exact_decision_accuracy']:.2%}\n"
        f"Safe-Decision Rate: {metrics['defended']['safe_decision_rate']:.2%}\n"
        f"False Accept Rate (FAR): {metrics['defended']['false_accept_rate']:.2%}\n"
        f"False Reject Rate (FRR): {metrics['defended']['false_reject_rate']:.2%}\n"
        f"Attack Detection Rate (ADR): {metrics['defended']['attack_detection_rate']:.2%}\n"
        f"Attack Success Rate (ASR): {metrics['defended']['attack_success_rate']:.2%}\n"
        f"Decision Matrix:\n{format_matrix(metrics['defended']['confusion_matrix'])}\n"
        
        "* Documented MFA Treatment:\n"
        "  - MFA counts as detected for suspicious/malicious cases because direct access is blocked.\n"
        "  - MFA counts as a false rejection for clean cases because successful completion is not simulated.\n"
        "  - Note: Logging an MFA result only means MFA was *requested*; it does not simulate or claim successful MFA authentication.\n\n"
        "* Disclaimer: Attack Success Rate (ASR) measures synthetic manipulated-input success, not general resistance to all adversarial or backdoor attacks.\n"
    )
    
    with open(f"{out_dir}/evaluation_summary.txt", "w") as f:
        f.write(summary_text)
        
    print(summary_text)
    
    # Optional Plot
    try:
        labels = ['Exact Acc', 'Safe Acc', 'FAR', 'FRR', 'ADR', 'ASR']
        b = metrics['baseline']
        d = metrics['defended']
        b_vals = [b['exact_decision_accuracy'], b['safe_decision_rate'], b['false_accept_rate'], b['false_reject_rate'], b['attack_detection_rate'], b['attack_success_rate']]
        d_vals = [d['exact_decision_accuracy'], d['safe_decision_rate'], d['false_accept_rate'], d['false_reject_rate'], d['attack_detection_rate'], d['attack_success_rate']]
        
        x = range(len(labels))
        width = 0.35
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar([i - width/2 for i in x], b_vals, width, label='Baseline')
        ax.bar([i + width/2 for i in x], d_vals, width, label='Defended')
        ax.set_ylabel('Scores')
        ax.set_title('Baseline vs Defended Mode Metrics (Corrected)')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend()
        plt.savefig(f"{out_dir}/evaluation_plot.png")
    except Exception as e:
        print("Could not generate plot:", e)

def run_tests():
    """Validates harness requirements."""
    df = generate_synthetic_data()
    assert len(df[df['category'] == 'clean']) > 0, "No clean examples represented."
    assert len(df[df['category'] == 'suspicious']) > 0, "No suspicious examples represented."
    assert len(df[df['category'] == 'malicious']) > 0, "No malicious examples represented."
    print("Validation passed: Data contains all required categories and synthetic features.")
    
if __name__ == "__main__":
    run_tests()
    evaluate()
