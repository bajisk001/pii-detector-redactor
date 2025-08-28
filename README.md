# Project Guardian 2.0 – PII Detector & Redactor

## Files in this Repo
- `detector_full_candidate_name.py` → Python script for detecting & redacting PII  
- `redacted_output_candidate_full_name.csv` → Generated output file  
- `DEPLOYMENT.md` → Deployment strategy document  
- `README.md` → Project overview  

## How to Run
```bash
python3 detector_full_candidate_name.py iscp_pii_dataset.csv
```bash
git init
git add .
git commit -m "Initial commit - PII detector project"
git branch -M main
git remote add origin https://github.com/bajisk001/pii-detector-redactor.git
git push -u origin main
