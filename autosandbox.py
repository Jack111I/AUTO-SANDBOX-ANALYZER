import os
import re
import magic
import hashlib

def get_file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()
    result = re.findall(rb"[ -~]{4,}", data)
    return [s.decode(errors="ignore") for s in result]

def detect_urls(strings):
    url_pattern = r"(https?://[^\s]+)"
    urls = []
    for s in strings:
        found = re.findall(url_pattern, s)
        urls.extend(found)
    return list(set(urls))

def detect_suspicious(strings):
    suspicious_list = [
        "CreateProcess", "VirtualAlloc", "ShellExecute", "WScript",
        "cmd.exe", "powershell", "socket", "spawn", "eval(", "base64"
    ]

    hits = []
    for line in strings:
        for s in suspicious_list:
            if s.lower() in line.lower():
                hits.append(line)
    return hits

def analyze_file(path):
    report = []
    report.append("# AutoSandbox Analyzer Report\n")

    # type
    file_type = magic.from_file(path)
    report.append(f"**File Type:** {file_type}\n")

    # hash
    sha = get_file_hash(path)
    report.append(f"**SHA256:** `{sha}`\n")

    # strings
    strings = extract_strings(path)
    report.append(f"**Extracted Strings:** {len(strings)} found\n")

    # URLs
    urls = detect_urls(strings)
    report.append("### URLs Found:\n" + "\n".join(urls) if urls else "### No URLs found\n")

    # suspicious indicators
    sus = detect_suspicious(strings)
    report.append("### Suspicious Indicators:\n" + "\n".join(sus) if sus else "### No suspicious patterns\n")

    return "\n".join(report)

if __name__ == "__main__":
    import sys
    file = sys.argv[1]
    result = analyze_file(file)
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/{os.path.basename(file)}_report.md", "w", encoding="utf-8") as f:
        f.write(result)
    print("Report saved in /reports/")
