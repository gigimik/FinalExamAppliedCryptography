import hashlib
import json
import sys
import os

HASH_FILE = "hashes.json"

def compute_hashes(filename):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256()
    }

    with open(filename, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)

    return {k: v.hexdigest() for k, v in hashes.items()}

def init_hashes(filename):
    hashes = compute_hashes(filename)
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)
    print("[+] Hashes generated and saved to hashes.json:")
    for k, v in hashes.items():
        print(f"    {k}: {v}")

def check_hashes(filename):
    if not os.path.exists(HASH_FILE):
        print("[-] hashes.json not found. Run init first.")
        return

    with open(HASH_FILE, "r") as f:
        saved = json.load(f)

    current = compute_hashes(filename)

    print("[*] Comparing hashes...\n")
    passed = True

    for algo in saved:
        print(f"{algo.upper():7} saved:   {saved[algo]}")
        print(f"{algo.upper():7} current: {current[algo]}\n")
        if saved[algo] != current[algo]:
            passed = False

    if passed:
        print("[+] INTEGRITY CHECK PASSED")
    else:
        print("[-] INTEGRITY CHECK FAILED — FILE WAS MODIFIED")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python hash_util.py init <filename>")
        print("  python hash_util.py check <filename>")
        sys.exit(1)

    cmd = sys.argv[1]
    file = sys.argv[2]

    if cmd == "init":
        init_hashes(file)
    elif cmd == "check":
        check_hashes(file)
    else:
        print("Unknown command. Use init or check.")
