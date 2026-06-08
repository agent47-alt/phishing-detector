import re
import requests
import os
import ssl
import socket
import datetime
import whois
from dotenv import load_dotenv

load_dotenv()

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account',
    'banking', 'confirm', 'password', 'signin', 'ebayisapi',
    'webscr', 'free', 'lucky', 'winner', 'click', 'paypal'
]

def analyze_url(url):
    reasons = []
    risk_score = 0

    # Check 1 — URL Length
    if len(url) > 75:
        reasons.append("URL is suspiciously long")
        risk_score += 20

    # Check 2 — Has IP address instead of domain
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        reasons.append("URL uses an IP address instead of a domain")
        risk_score += 30

    # Check 3 — Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            reasons.append(f"Contains suspicious keyword: '{keyword}'")
            risk_score += 15
            break

    # Check 4 — No HTTPS
    if not url.startswith('https'):
        reasons.append("URL does not use HTTPS")
        risk_score += 20

    # Check 5 — Too many dots
    if url.count('.') > 4:
        reasons.append("URL has too many dots (possible subdomain attack)")
        risk_score += 15

    # Check 6 — Has @ symbol
    if '@' in url:
        reasons.append("URL contains @ symbol (phishing trick)")
        risk_score += 30

    # Check 7 — SSL Certificate
    ssl_info = check_ssl(url)
    if ssl_info['error']:
        reasons.append(f"SSL Error: {ssl_info['error']}")
        risk_score += 20
    elif ssl_info['expired']:
        reasons.append("SSL certificate is expired!")
        risk_score += 30
    elif ssl_info['expires_soon']:
        reasons.append(f"SSL certificate expires soon: {ssl_info['expiry_date']}")
        risk_score += 10

    # Check 8 — Google Safe Browsing API
    api_key = os.getenv('GOOGLE_API_KEY')
    if api_key:
        gsb_result = check_google_safe_browsing(url, api_key)
        if gsb_result:
            reasons.append("⚠️ Flagged by Google Safe Browsing!")
            risk_score += 50

    # Cap score at 100
    risk_score = min(risk_score, 100)
    is_phishing = risk_score >= 50

    return {
        'risk_score': risk_score,
        'is_phishing': is_phishing,
        'reasons': reasons
    }


def check_ssl(url):
    result = {
        'error': None,
        'expired': False,
        'expires_soon': False,
        'expiry_date': None,
        'valid': False
    }
    try:
        if not url.startswith('https'):
            result['error'] = 'Not an HTTPS URL'
            return result

        import tldextract
        extracted = tldextract.extract(url)
        hostname = f"{extracted.domain}.{extracted.suffix}"

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(
                    expiry_str, '%b %d %H:%M:%S %Y %Z'
                )
                now = datetime.datetime.utcnow()
                days_left = (expiry_date - now).days

                result['valid'] = True
                result['expiry_date'] = expiry_date.strftime('%d %b %Y')

                if days_left < 0:
                    result['expired'] = True
                elif days_left < 30:
                    result['expires_soon'] = True

    except ssl.SSLCertVerificationError:
        result['error'] = 'Invalid SSL certificate'
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except Exception:
        result['error'] = None

    return result


def check_google_safe_browsing(url, api_key):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload)
        data = response.json()
        return bool(data.get('matches'))
    except:
        return False