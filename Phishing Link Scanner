import re
from urllib.parse import urlparse

def is_ip_address(domain):
    # Check if domain is an IP address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(ip_pattern.match(domain))

def contains_suspicious_keywords(url):
    suspicious_keywords = ['login', 'verify', 'update', 'free', 'account', 'secure', 'ebayisapi', 'webscr']
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in suspicious_keywords)

def is_shortened_url(domain):
    # Common URL shortening services
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'bitly.com', 'is.gd', 'buff.ly']
    return domain in shorteners

def scan_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    results = {}

    # Check if domain is IP address
    results['ip_address'] = is_ip_address(domain)

    # Check URL length
    results['long_url'] = len(url) > 75

    # Check for suspicious keywords
    results['suspicious_keywords'] = contains_suspicious_keywords(url)

    # Check if URL uses HTTPS
    results['https'] = parsed.scheme == 'https'

    # Check if URL is shortened
    results['shortened_url'] = is_shortened_url(domain)

    # Simple phishing suspicion score
    suspicion_score = sum(results.values())

    results['suspicion_score'] = suspicion_score
    results['is_phishing'] = suspicion_score >= 2  # Threshold can be adjusted

    return results

if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login",
        "https://bit.ly/3xYzAbC",
        "https://secure-paypal.com/verify",
        "http://example.com/free-stuff",
        "https://google.com",
    ]

    for url in test_urls:
        result = scan_url(url)
        print(f"URL: {url}")
        print(f"Scan Result: {result}")
        print("-" * 40)
