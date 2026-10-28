from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    type: str = "url"

def analyze_url(url: str):
    url_lower = url.lower()
    risk = 0
    threat = "No match"
    status = "Safe"

    # --- INDIAN SCAM DATABASE ---
    if "kbc" in url_lower and "lottery" in url_lower:
        return {"status": "Critical", "riskScore": 98, "threatType": "KBC Lottery Fraud", "advice": "KBC never asks for money online. This is 100% fraud."}
    
    if "sbi" in url_lower and ("yono" in url_lower or "reward" in url_lower or "kyc" in url_lower):
        return {"status": "Critical", "riskScore": 95, "threatType": "SBI YONO Phishing", "advice": "Fake SBI site! Official SBI is only sbi.co.in. Don't enter password."}

    if ("paytm" in url_lower or "phonepe" in url_lower or "gpay" in url_lower) and ("kyc" in url_lower or "cashback" in url_lower or "reward" in url_lower):
        return {"status": "Dangerous", "riskScore": 90, "threatType": "Paytm KYC Fake", "advice": "Paytm never blocks KYC via link. Open official app directly."}

    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url_lower) or url_lower.count('.') > 4:
        return {"status": "Suspicious", "riskScore": 80, "threatType": "IP Address Host", "advice": "Link uses IP address or too many subdomains. Highly suspicious."}

    if any(x in url_lower for x in ["work-from-home", "5000-per-day", "lottery-winner"]):
        return {"status": "Dangerous", "riskScore": 88, "threatType": "Job/Lottery Scam", "advice": "No real lottery asks for fees online."}

    return {"status": "Safe", "riskScore": 5, "threatType": "No match", "advice": "No strong threats detected, but always verify links before sharing personal info."}

@app.get("/")
def home():
    return {"message": "CyberShield Backend Running"}

@app.post("/scan")
def scan(req: ScanRequest):
    result = analyze_url(req.url)
    # save to DB ka code hata do abhi ke liye taaki "Could not save" error na aaye
    return result
