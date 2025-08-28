#!/usr/bin/env python3
import sys
import re
import csv
import json

# --- Regex patterns for standalone PII ---
PII_PATTERNS = {
    "phone": re.compile(r"\b\d{10}\b"),
    "aadhar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "passport": re.compile(r"\b[A-PR-WY][1-9]\d{6}\b", re.I),  # e.g., P1234567
    "upi_id": re.compile(r"\b[\w\.\-]{2,}@[a-z]{2,}\b", re.I),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# --- Helper functions ---
def mask_phone(num: str) -> str:
    return num[:2] + "XXXXXX" + num[-2:]

def mask_aadhar(num: str) -> str:
    return num[:4] + " XXXX XXXX"

def mask_passport(num: str) -> str:
    return num[0] + "XXXXXXX"

def mask_upi(upi: str) -> str:
    return upi[0:2] + "XXXX@" + upi.split("@")[1]

def mask_name(name: str) -> str:
    parts = name.split()
    return " ".join([p[0] + "XXX" for p in parts])

def mask_email(email: str) -> str:
    user, domain = email.split("@")
    return user[:2] + "XXX@" + domain

def redact_value(key, val):
    """Return masked value if PII detected"""
    if key == "phone" and PII_PATTERNS["phone"].search(val):
        return mask_phone(val), True
    if key == "aadhar" and PII_PATTERNS["aadhar"].search(val):
        return mask_aadhar(val), True
    if key == "passport" and PII_PATTERNS["passport"].search(val):
        return mask_passport(val), True
    if key == "upi_id" and PII_PATTERNS["upi_id"].search(val):
        return mask_upi(val), True
    if key == "name" and len(val.split()) >= 2:  # Full name
        return mask_name(val), True
    if key == "email" and re.search(r"[^@]+@[^@]+\.[^@]+", val):
        return mask_email(val), True
    if key == "address" and len(val.split()) > 2:
        return "[REDACTED_PII]", True
    if key == "ip_address" and PII_PATTERNS["ip_address"].search(val):
        return "[REDACTED_PII]", True
    return val, False

def process_record(data: dict):
    """Check if record contains PII and redact"""
    is_pii = False
    new_data = {}
    detected = set()

    for key, val in data.items():
        if isinstance(val, str):
            redacted, flag = redact_value(key, val)
            new_data[key] = redacted
            if flag:
                is_pii = True
                detected.add(key)
        else:
            new_data[key] = val

    # Combinatorial PII check (Name + Email, Name + Address, etc.)
    if ("name" in detected and "email" in data) or ("name" in detected and "address" in data):
        is_pii = True

    return new_data, is_pii

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py input.csv")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"

    with open(input_csv, "r", encoding="utf-8") as infile, open(output_csv, "w", newline="", encoding="utf-8") as outfile:
        reader = csv.DictReader(infile)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_id = row.get("record_id") or row.get("Record_id") or row.get("id")
            raw_json = row.get("Data_json") or row.get("data_json")  # <---- FIX HERE

            try:
                data = json.loads(raw_json)
            except Exception:
                data = {}

            redacted_data, is_pii = process_record(data)

            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": json.dumps(redacted_data),
                "is_pii": str(is_pii)
            })


if __name__ == "__main__":
    main()
