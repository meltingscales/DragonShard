from recon.scanner import run_scan

if __name__ == "__main__":
    target = "127.0.0.1"
    print(f"[*] Starting recon on {target}")
    result = run_scan(target)
    print(result)
