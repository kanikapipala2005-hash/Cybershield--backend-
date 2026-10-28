from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests, os, re
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="CyberShield Real API", version="1.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

VT_KEY = os.getenv("VT_API_KEY", "")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY", "")

def ml_phishing_score(url: str):
    score = 0
    reasons = []
    if len(url) > 75:
        score += 20; reasons.append("Long URL")
    if "@" in url:
        score += 30; reasons.append("Contains @")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 30; reasons.append("IP in URL")
    if url.count(".") > 4:
        score += 15; reasons.append("Many subdomains")
    if any(w in url.lower() for w in ["login","secure","account","verify","free","bonus"]):
        score += 15; reasons.append("Suspicious keywords")
    if not url.startswith("https"):
        score += 10; reasons.append("No HTTPS")
    return min(score, 100), reasons

@app.get("/")
def home():
    return {"status": "CyberShield Real API Running"}

@app.get("/scan/url")
def scan_url(url: str):
    if not url.startswith("http"):
        url = "https://" + url
    ml_score, reasons = ml_phishing_score(url)
    
    vt_result, malicious_count = None, 0
    try:
        if VT_KEY:
            headers = {"x-apikey": VT_KEY}
            r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
            if r.status_code == 200:
                analysis_id = r.json()["data"]["id"]
                report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10).json()
                vt_result = report["data"]["attributes"]["stats"]
                malicious_count = vt_result.get("malicious", 0)
    except Exception as e:
        vt_result = {"error": str(e)}

    total_risk = ml_score + (malicious_count * 10)
    verdict = "MALICIOUS" if malicious_count > 3 or total_risk >= 70 else "SUSPICIOUS" if total_risk >= 35 else "SAFE"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": total_risk,
        "ml_score": ml_score,
        "ml_reasons": reasons,
        "virustotal": vt_result,
        "vt_flagged": f"{malicious_count}/90"
    }

@app.get("/scan/ip")
def scan_ip(ip: str):
    if not ABUSE_KEY:
        return {"ip": ip, "demo": True, "message": "Add ABUSEIPDB_KEY for real data"}
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params={"ipAddress": ip}, timeout=10)
    data = r.json()["data"]
    return {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),
        "verdict": "MALICIOUS" if data.get("abuseConfidenceScore",0) > 50 else "SAFE"
    }
def check_threat(url):
    url = url.lower()
    
    if "sbi" in url and ("yono" in url or "reward" in url or "kyc" in url):
        return {
            "status": "Critical",
            "riskScore": 95,
            "threatType": "SBI YONO Phishing",
            "advice": "This is a fake SBI site! Never enter your credentials."
        }
    
    if "paytm" in url and "kyc" in url:
        return {
            "status": "Dangerous", 
            "riskScore": 90,
            "threatType": "Paytm KYC Fraud"
        }
    
    if url.count('.') > 3 or "192.168" in url or url.replace('.','').replace('/','').replace(':','').isdigit():
        return {
            "status": "Suspicious",
            "riskScore": 75,
            "threatType": "IP Address Host"
        }

    return {"status": "Safe", "riskScore": 0, "threatType": "No match"}
