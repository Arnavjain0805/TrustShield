from defense import evaluate_input_robustness

def run_tests():
    print("Running defense layer tests...\n")
    
    # Test 1: Normal input
    ip = "192.168.1.1"
    device = "Windows PC"
    browser = "Chrome"
    hour = 14
    severity, suspicious, reasons = evaluate_input_robustness(ip, device, browser, hour)
    print(f"Test 1 (Normal Input): Expected ALLOW, Got {severity}")
    assert severity == "ALLOW"
    assert not suspicious
    print(" -> PASSED\n")
    
    # Test 2: Suspicious input (MFA expected)
    ip = "192.168.1.1"
    device = "Windows PC      " # Excessive whitespace
    browser = "Chrooooomme" # Repeated characters
    hour = 14
    severity, suspicious, reasons = evaluate_input_robustness(ip, device, browser, hour)
    print(f"Test 2 (Suspicious Input): Expected MFA, Got {severity}")
    assert severity == "MFA"
    assert suspicious
    print(f" -> Reasons: {reasons}")
    print(" -> PASSED\n")
    
    # Test 3: Malicious input (BLOCK expected) - Invalid Hour
    hour = 25
    severity, suspicious, reasons = evaluate_input_robustness(ip, device, browser, hour)
    print(f"Test 3a (Malicious Input - Hour): Expected BLOCK, Got {severity}")
    assert severity == "BLOCK"
    assert suspicious
    print(f" -> Reasons: {reasons}")
    print(" -> PASSED\n")

    # Test 3b: Malicious input (BLOCK expected) - Injection
    hour = 14
    device = "<script>alert(1)</script>"
    severity, suspicious, reasons = evaluate_input_robustness(ip, device, browser, hour)
    print(f"Test 3b (Malicious Input - Injection): Expected BLOCK, Got {severity}")
    assert severity == "BLOCK"
    assert suspicious
    print(f" -> Reasons: {reasons}")
    print(" -> PASSED\n")

    print("All tests passed successfully!")

if __name__ == "__main__":
    run_tests()
