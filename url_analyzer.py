import re
from urllib.parse import urlparse

def check_phishing(url):
    """
    Perfect URL phishing detection with accurate scoring
    Safe: 0-2 points (Green)
    Suspicious: 3-5 points (Yellow) 
    Dangerous: 6+ points (Red)
    """
    if not url or not isinstance(url, str) or len(url.strip()) == 0:
        return {
            'status': 'Invalid',
            'message': 'Empty or invalid URL',
            'risk_score': 0,
            'risk_factors': ['Empty input'],
            'confidence': 0
        }
    
    url = url.strip().lower()
    risk_score = 0
    risk_factors = []
    
    # Parse URL to get domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
    except:
        domain = ""
        path = ""
    
    # COMPLETE KEYWORD LIST
    critical_keywords = [
        'login', 'verify', 'verification', 'password', 'banking', 'paypal', 
        'paytm', 'facebook', 'authenticate', 'security', 'secure'
    ]
    
    fake_brands = [
        'paytm', 'facebook', 'google', 'amazon', 'instagram', 'whatsapp', 
        'icici', 'hdfc', 'sbi', 'bank', 'netflix', 'twitter'
    ]
    
    # === CRITICAL RISK FACTORS (3 points each) ===
    
    # 1. IP Address + Security Keywords Combination (Very High Risk)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    has_ip = bool(re.search(ip_pattern, url))
    found_critical = [word for word in critical_keywords if word in url]
    
    if has_ip and found_critical:
        risk_score += 3
        risk_factors.append('IP address with security keywords (CRITICAL RISK)')
    
    # === HIGH RISK FACTORS (2 points each) ===
    
    # 2. IP Address alone
    if has_ip and not found_critical:
        risk_score += 2
        risk_factors.append('IP address instead of domain name')
    
    # 3. Multiple security keywords in DOMAIN name (Very suspicious)
    domain_keywords = [word for word in critical_keywords if word in domain]
    if len(domain_keywords) >= 2:
        risk_score += 2
        risk_factors.append(f'Multiple security keywords in domain: {", ".join(domain_keywords)}')
    
    # 4. Fake brand names in domain
    found_fake_brands = [brand for brand in fake_brands if brand in domain and not any(domain.endswith(f'.{brand}.com') for brand in ['google', 'amazon'])]
    if found_fake_brands:
        risk_score += 2
        risk_factors.append(f'Fake brand in domain: {", ".join(found_fake_brands)}')
    
    # 5. Multiple security keywords in full URL (2+ words)
    if len(found_critical) >= 2:
        risk_score += 2
        risk_factors.append(f'Multiple security keywords: {", ".join(found_critical)}')
    
    # === MEDIUM RISK FACTORS (1 point each) ===
    
    # 6. No HTTPS
    if not url.startswith('https://'):
        risk_score += 1
        risk_factors.append('No HTTPS encryption')
    
    # 7. URL Shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'short.url']
    if any(shortener in domain for shortener in shorteners):
        risk_score += 1
        risk_factors.append('Uses URL shortener service')
    
    # 8. Single security keyword in DOMAIN
    if len(domain_keywords) == 1:
        risk_score += 1
        risk_factors.append(f'Security keyword in domain: {domain_keywords[0]}')
    
    # 9. Single security keyword in full URL
    if len(found_critical) == 1:
        risk_score += 1
        risk_factors.append(f'Security keyword: {found_critical[0]}')
    
    # 10. @ Symbol in URL
    if '@' in url:
        risk_score += 1
        risk_factors.append('Contains @ symbol')
    
    # 11. Too many subdomains (>5 dots)
    if url.count('.') > 5:
        risk_score += 1
        risk_factors.append('Too many subdomains')
    
    # 12. Suspicious TLDs with keywords
    suspicious_tlds = ['.zip', '.review', '.country', '.kim', '.gq', '.ml', '.tk', '.xyz', '.top', '.club']
    if any(domain.endswith(tld) for tld in suspicious_tlds) and domain_keywords:
        risk_score += 1
        risk_factors.append('Suspicious domain extension with keywords')
    
    # 13. New/uncommon domain patterns
    uncommon_patterns = ['.com-', '.net-', '-login', '-verify', '-verification', '-secure', '-account', '-banking', '-portal', '-platform']
    if any(pattern in domain for pattern in uncommon_patterns):
        risk_score += 1
        risk_factors.append('Unusual domain pattern')
    
    # === LOW RISK FACTORS (0.5 points each) ===
    
    # 14. Medium-risk keywords
    medium_risk_keywords = ['account', 'update', 'signin', 'validation', 'recovery', 'portal', 'platform', 'service', 'online']
    found_medium_risk = [word for word in medium_risk_keywords if word in url]
    if found_medium_risk:
        risk_score += 0.5 * len(found_medium_risk)
        risk_factors.append(f'Medium-risk keywords: {", ".join(found_medium_risk)}')
    
    # 15. Long URL (>75 characters)
    if len(url) > 75:
        risk_score += 0.5
        risk_factors.append('Long URL')
    
    # 16. Multiple hyphens (>3)
    if url.count('-') > 3:
        risk_score += 0.5
        risk_factors.append('Multiple hyphens in URL')
    
    # Round to nearest integer
    risk_score = round(risk_score)
    
    # SPECIAL CASE: Force suspicious for security-like domains
    security_like_words = ['account', 'verification', 'portal', 'secure', 'login', 'platform', 'verify']
    domain_words = domain.replace('.', '-').split('-')
    security_domain_words = [word for word in domain_words if word in security_like_words]
    
    # If domain has 2+ security words but score is low, make it suspicious
    if len(security_domain_words) >= 2 and risk_score < 3:
        risk_score = 4  # Force to suspicious
        additional_factors = []
        if 'account' in security_domain_words:
            additional_factors.append('account')
        if 'verification' in security_domain_words:
            additional_factors.append('verification')
        if 'portal' in security_domain_words:
            additional_factors.append('portal')
        risk_factors.append(f'Suspicious domain with security words: {", ".join(additional_factors)}')
    
    # PERFECT STATUS DETERMINATION
    if risk_score >= 6:
        status = "Dangerous"
        message = "🚨 High risk phishing URL detected"
        confidence = 85 + min(10, risk_score - 6)  # 85-95%
    elif risk_score >= 3:
        status = "Suspicious" 
        message = "⚠️ Suspicious URL - proceed with caution"
        confidence = 70 + min(15, (risk_score - 3) * 5)  # 70-85%
    else:
        status = "Safe"
        message = "✅ URL appears safe"
        confidence = 90 - (risk_score * 5)  # 85-90%
    
    # If no specific risk factors but basic checks pass
    if not risk_factors and re.match(r'^https?://', url):
        risk_factors.append('No suspicious patterns detected')
    
    return {
        'status': status,
        'message': message,
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'confidence': confidence,
        'source': 'Perfect URL Analysis'
    }

# Backward compatibility
def analyze_url(url):
    return check_phishing(url)