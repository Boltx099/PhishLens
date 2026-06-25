"""
PhishLens - Email Parser & IOC Extractor
Core analysis engine
"""

import email
import re
import hashlib
import base64
import quopri
import io
from email import policy
from email.header import decode_header
from datetime import datetime
from typing import Optional
import mailparser

try:
    import extract_msg as _extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False


# ─── .msg → RFC822 converter ──────────────────────────────────────────────────

def msg_to_eml(raw: bytes) -> bytes:
    """Convert Outlook .msg bytes to RFC822 .eml bytes for unified parsing."""
    if not MSG_SUPPORT:
        raise RuntimeError("extract-msg not installed. Run: pip install extract-msg")

    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        m = _extract_msg.openMsg(tmp)
        lines = []

        def _h(k, v):
            if v: lines.append(f"{k}: {v}")

        _h("From",       m.sender or "")
        _h("To",         m.to or "")
        _h("CC",         m.cc or "")
        _h("Subject",    m.subject or "")
        _h("Date",       str(m.date) if m.date else "")
        _h("Message-ID", m.messageId or "")
        _h("Reply-To",   m.replyTo or "")

        # Try to pull auth headers from transport headers
        if hasattr(m, 'header') and m.header:
            raw_hdr = m.header if isinstance(m.header, str) else m.header.decode('utf-8', errors='replace')
            for line in raw_hdr.splitlines():
                if any(line.lower().startswith(p) for p in
                       ('received:', 'authentication-results:', 'received-spf:',
                        'x-originating-ip:', 'x-mailer:', 'dkim-signature:')):
                    lines.append(line)

        lines.append("")  # blank line before body

        # Body
        body = m.htmlBody or m.body or b""
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='replace')
        lines.append(body)

        # Attachments — re-encode into MIME
        eml_bytes = "\r\n".join(lines).encode('utf-8', errors='replace')

        # If attachments exist, build a proper MIME message
        if m.attachments:
            import email.mime.multipart
            import email.mime.text
            import email.mime.base
            import email.encoders

            mime = email.mime.multipart.MIMEMultipart()
            mime['From']    = m.sender or ""
            mime['To']      = m.to or ""
            mime['Subject'] = m.subject or ""
            mime['Date']    = str(m.date) if m.date else ""

            html = m.htmlBody or b""
            txt  = m.body or b""
            if html:
                if isinstance(html, bytes): html = html.decode('utf-8', errors='replace')
                mime.attach(email.mime.text.MIMEText(html, 'html', 'utf-8'))
            elif txt:
                if isinstance(txt, bytes): txt = txt.decode('utf-8', errors='replace')
                mime.attach(email.mime.text.MIMEText(txt, 'plain', 'utf-8'))

            for att in m.attachments:
                try:
                    part = email.mime.base.MIMEBase('application', 'octet-stream')
                    att_data = att.data if hasattr(att, 'data') else b""
                    part.set_payload(att_data or b"")
                    email.encoders.encode_base64(part)
                    fname = att.longFilename or att.shortFilename or "attachment"
                    part.add_header('Content-Disposition', 'attachment', filename=fname)
                    mime.attach(part)
                except Exception:
                    pass

            eml_bytes = mime.as_bytes()

        return eml_bytes
    finally:
        os.unlink(tmp)
        try:
            m.close()
        except Exception:
            pass

# ─── Regex Patterns ───────────────────────────────────────────────────────────

URL_RE = re.compile(
    r'https?://[^\s<>"\')\]}{,;]+',
    re.IGNORECASE
)
DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|uk|de|ru|cn|info|biz|xyz|top|club|online|site|live|app|dev|ai|edu|gov|mil|int|arpa|[a-z]{2})\b',
    re.IGNORECASE
)
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# ─── Brand + Lookalike Detection ─────────────────────────────────────────────

# Known brands and their legitimate sending domains
BRAND_DOMAINS = {
    'paypal':     ['paypal.com'],
    'google':     ['google.com', 'gmail.com', 'googlemail.com', 'accounts.google.com'],
    'microsoft':  ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'office365.com'],
    'apple':      ['apple.com', 'icloud.com'],
    'amazon':     ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com'],
    'netflix':    ['netflix.com'],
    'facebook':   ['facebook.com', 'fb.com', 'meta.com'],
    'instagram':  ['instagram.com'],
    'twitter':    ['twitter.com', 'x.com'],
    'linkedin':   ['linkedin.com'],
    'dropbox':    ['dropbox.com'],
    'docusign':   ['docusign.com', 'docusign.net'],
    'fedex':      ['fedex.com'],
    'dhl':        ['dhl.com', 'dhl.de'],
    'ups':        ['ups.com'],
    'usps':       ['usps.com'],
    'irs':        ['irs.gov'],
    'chase':      ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'citibank':   ['citi.com', 'citibank.com'],
    'hsbc':       ['hsbc.com'],
    'norton':     ['norton.com', 'nortonlifelock.com'],
    'mcafee':     ['mcafee.com'],
    'steam':      ['steampowered.com', 'steamcommunity.com'],
}

# Homograph / char-substitution lookalike patterns → legitimate brand
LOOKALIKE_PATTERNS = [
    # number substitutions
    (r'pay\s*pa[l1]', 'paypal'),
    (r'g[o0][o0]g[l1]e', 'google'),
    (r'[a@]m[a@]z[o0]n', 'amazon'),
    (r'm[i1]cr[o0]s[o0]ft', 'microsoft'),
    (r'[a@]pp[l1]e', 'apple'),
    (r'[f]ace?b[o0][o0]k', 'facebook'),
    (r'netf[l1][i1]x', 'netflix'),
    (r'[l1][i1]nked[i1]n', 'linkedin'),
    (r'dr[o0]pb[o0]x', 'dropbox'),
    (r'[i1]nst[a@]gr[a@]m', 'instagram'),
    # common combo tricks
    (r'paypal[.-]', 'paypal'),
    (r'[.-]paypal', 'paypal'),
    (r'secure[.-]?paypal', 'paypal'),
    (r'google[.-]?(account|verify|sign)', 'google'),
    (r'microsoft[.-]?(account|365|secure)', 'microsoft'),
    (r'apple[.-]?(id|verify|secure|support)', 'apple'),
    (r'amazon[.-]?(account|prime|verify|secure)', 'amazon'),
]

# Phishing keyword categories with individual weights
# Each category caps at its max_points to prevent single-vector over-scoring
KEYWORD_CATEGORIES = {
    'credential_harvest': {
        'max_points': 20, 'severity': 'high',
        'keywords': [
            'verify your account', 'confirm your identity', 'verify your email',
            'confirm your email', 'verify your password', 'confirm your password',
            'verify your details', 'verify your information',
            'account verification required', 'identity verification',
            'complete verification', 'verify now', 'confirm now',
        ]
    },
    'account_threat': {
        'max_points': 15, 'severity': 'medium',
        'keywords': [
            'your account has been suspended', 'your account has been locked',
            'your account has been disabled', 'your account will be suspended',
            'unauthorized access', 'unusual sign-in activity', 'unusual activity detected',
            'suspicious activity', 'we noticed unusual', 'security alert',
            'account access limited', 'account temporarily limited',
        ]
    },
    'urgency_pressure': {
        'max_points': 10, 'severity': 'medium',
        'keywords': [
            'immediate action required', 'action required within',
            'respond within 24 hours', 'respond within 48 hours',
            'failure to verify', 'failure to confirm', 'will result in',
            'your account will be', 'or your account',
        ]
    },
    'financial_scam': {
        'max_points': 20, 'severity': 'high',
        'keywords': [
            'wire transfer', 'bank transfer', 'western union', 'money gram',
            'gift card', 'itunes card', 'google play card', 'amazon gift card',
            'nigerian prince', 'inheritance funds', 'million dollars', 'million usd',
            'beneficiary', 'next of kin', 'unclaimed funds',
            'investment opportunity', 'double your money',
        ]
    },
    'prize_scam': {
        'max_points': 15, 'severity': 'medium',
        'keywords': [
            'you have won', 'you are a winner', 'you have been selected',
            'congratulations you', 'claim your prize', 'claim your reward',
            'free iphone', 'free gift card', 'lottery winner',
        ]
    },
    'credential_request': {
        'max_points': 15, 'severity': 'high',
        'keywords': [
            'enter your password', 'enter your username', 'enter your credentials',
            'provide your details', 'update your payment', 'update your billing',
            'confirm your card', 'credit card information', 'enter your ssn',
            'social security number', 'enter your pin',
        ]
    },
}

# Suspicious keywords in subject/body (legacy — keep for backward compat)
PHISH_KEYWORDS = [kw for cat in KEYWORD_CATEGORIES.values() for kw in cat['keywords']]

DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh',
    '.msi', '.msp', '.scr', '.pif', '.com', '.ps1', '.psm1',
    '.hta', '.reg', '.lnk', '.docm', '.xlsm', '.pptm'
}

SUSPICIOUS_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.gz', '.tar', '.iso', '.img',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
}


def decode_str(s) -> str:
    """Safely decode email header strings."""
    if s is None:
        return ''
    if isinstance(s, bytes):
        return s.decode('utf-8', errors='replace')
    parts = decode_header(s)
    result = []
    for part, charset in parts:
        if isinstance(part, bytes):
            charset = charset or 'utf-8'
            try:
                result.append(part.decode(charset, errors='replace'))
            except Exception:
                result.append(part.decode('utf-8', errors='replace'))
        else:
            result.append(str(part))
    return ''.join(result)


def extract_iocs(text: str) -> dict:
    """Extract all IOCs from text blob."""
    urls = list(set(URL_RE.findall(text)))
    ips = list(set(IP_RE.findall(text)))
    emails = list(set(EMAIL_RE.findall(text)))
    
    # Domains — deduplicate against URLs
    raw_domains = list(set(DOMAIN_RE.findall(text)))
    # Filter out domains already in URLs and common FPs
    url_domains = set()
    for url in urls:
        m = re.search(r'https?://([^/?\s]+)', url)
        if m:
            url_domains.add(m.group(1).lower())
    
    domains = [d for d in raw_domains 
               if d.lower() not in url_domains 
               and len(d) > 4
               and '.' in d]
    
    return {
        'urls': sorted(urls),
        'ips': sorted(ips),
        'emails': sorted(emails),
        'domains': sorted(set(domains))
    }


def check_keywords(text: str) -> list:
    """Check for phishing keywords — returns matched keywords (legacy compat)."""
    text_lower = text.lower()
    found = []
    for kw in PHISH_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return found


def check_keywords_weighted(text: str) -> dict:
    """
    Weighted keyword analysis by category.
    Returns per-category hits and total capped score contribution.
    """
    text_lower = text.lower()
    results = {}
    total_score = 0
    matched_keywords = []

    for cat_name, cat in KEYWORD_CATEGORIES.items():
        hits = [kw for kw in cat['keywords'] if kw in text_lower]
        if hits:
            # Score scales with number of hits but caps at category max
            raw = min(len(hits), 3) / 3 * cat['max_points']
            pts = round(raw)
            results[cat_name] = {
                'hits': hits,
                'points': pts,
                'severity': cat['severity'],
                'max': cat['max_points'],
            }
            total_score += pts
            matched_keywords.extend(hits)

    return {
        'categories': results,
        'total_score': min(total_score, 35),  # global keyword cap: 35pts
        'matched': list(set(matched_keywords)),
    }


def analyze_received_chain(msg) -> list:
    """Parse Received headers to build hop chain."""
    received = msg.get_all('Received', [])
    hops = []
    for r in received:
        r = decode_str(r)
        hop = {'raw': r, 'ip': None, 'from': None, 'by': None, 'time': None}
        
        ip_match = IP_RE.search(r)
        if ip_match:
            hop['ip'] = ip_match.group()
        
        from_match = re.search(r'from\s+(\S+)', r, re.IGNORECASE)
        if from_match:
            hop['from'] = from_match.group(1)
        
        by_match = re.search(r'by\s+(\S+)', r, re.IGNORECASE)
        if by_match:
            hop['by'] = by_match.group(1)
        
        hops.append(hop)
    return hops


def check_auth_headers(msg) -> dict:
    """Parse SPF, DKIM, DMARC from Authentication-Results."""
    auth_results = msg.get('Authentication-Results', '')
    auth_str = decode_str(auth_results).lower()
    
    result = {
        'spf': 'none',
        'dkim': 'none', 
        'dmarc': 'none',
        'raw': decode_str(auth_results)
    }
    
    # SPF
    spf_match = re.search(r'spf=(\w+)', auth_str)
    if spf_match:
        result['spf'] = spf_match.group(1)
    else:
        # Also check X-Received-SPF
        spf_header = msg.get('Received-SPF', '') or msg.get('X-Received-SPF', '')
        if spf_header:
            spf_str = decode_str(spf_header).lower()
            for status in ['pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror']:
                if status in spf_str:
                    result['spf'] = status
                    break
    
    # DKIM
    dkim_match = re.search(r'dkim=(\w+)', auth_str)
    if dkim_match:
        result['dkim'] = dkim_match.group(1)
    
    # DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', auth_str)
    if dmarc_match:
        result['dmarc'] = dmarc_match.group(1)
    
    return result


def check_display_name_spoof(from_header: str, reply_to: str) -> dict:
    """Detect display name spoofing and reply-to mismatch."""
    issues = []

    display_match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>', from_header)
    if display_match:
        display_name = display_match.group(1).strip()
        actual_email = display_match.group(2).strip()

        display_domain_match = re.search(r'@([\w.]+)', display_name)
        actual_domain_match  = re.search(r'@([\w.]+)', actual_email)

        if display_domain_match and actual_domain_match:
            if display_domain_match.group(1).lower() != actual_domain_match.group(1).lower():
                issues.append({
                    'type': 'domain_mismatch',
                    'detail': f'Display shows @{display_domain_match.group(1)} but sent from @{actual_domain_match.group(1)}'
                })

        if reply_to:
            reply_domain = re.search(r'@([\w.]+)', reply_to)
            if reply_domain and actual_domain_match:
                if reply_domain.group(1).lower() != actual_domain_match.group(1).lower():
                    issues.append({
                        'type': 'reply_to_mismatch',
                        'detail': f'Reply-To domain ({reply_domain.group(1)}) differs from From domain ({actual_domain_match.group(1)})'
                    })

    return {
        'spoofed': len(issues) > 0,
        'issues': issues,
        'from_parsed': {
            'display': display_match.group(1).strip() if display_match else '',
            'email':   display_match.group(2).strip() if display_match else from_header,
        }
    }


def check_brand_impersonation(from_header: str, subject: str, body_text: str,
                               urls: list) -> dict:
    """
    Detect brand impersonation:
    - Display name claims to be a known brand but sends from unrelated domain
    - Lookalike / homograph domain in From or URLs
    - IDN / punycode domain in From or URLs
    """
    findings = []
    impersonated_brands = set()

    # Extract actual sending domain
    from_match = re.search(r'<[^>]*@([\w.\-]+)>', from_header)
    if not from_match:
        from_match = re.search(r'@([\w.\-]+)', from_header)
    sending_domain = from_match.group(1).lower() if from_match else ''

    # Display name contains brand but sends from wrong domain
    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    display_name = display_match.group(1).strip().lower() if display_match else ''

    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in display_name or brand in subject.lower():
            # Check if actually coming from legit domain
            is_legit = any(
                sending_domain == ld or sending_domain.endswith('.' + ld)
                for ld in legit_domains
            )
            if not is_legit and sending_domain:
                findings.append({
                    'type': 'display_name_impersonation',
                    'brand': brand,
                    'detail': f'Claiming to be {brand} but sending from {sending_domain}',
                    'severity': 'critical',
                })
                impersonated_brands.add(brand)

    # Lookalike domain check — From header + URLs
    all_domains = [sending_domain] + [
        re.search(r'https?://([^/?\s]+)', u).group(1).lower()
        for u in urls
        if re.search(r'https?://([^/?\s]+)', u)
    ]
    for domain in all_domains:
        for pattern, brand in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                # Only flag if domain is NOT the actual legit domain
                legit = BRAND_DOMAINS.get(brand, [])
                is_legit = any(domain == ld or domain.endswith('.' + ld) for ld in legit)
                if not is_legit:
                    findings.append({
                        'type': 'lookalike_domain',
                        'brand': brand,
                        'detail': f'Domain "{domain}" appears to impersonate {brand}',
                        'severity': 'critical',
                    })
                    impersonated_brands.add(brand)

    # IDN / Punycode detection
    for domain in all_domains:
        if 'xn--' in domain:
            findings.append({
                'type': 'punycode_idn',
                'brand': None,
                'detail': f'Punycode/IDN domain detected: {domain} — possible homograph attack',
                'severity': 'high',
            })

    # Deduplicate findings
    seen = set()
    unique = []
    for f in findings:
        key = (f['type'], f.get('brand'), f.get('detail'))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        'impersonated_brands': list(impersonated_brands),
        'findings': unique,
    }


def analyze_urls(urls: list) -> list:
    """Analyze URLs for suspicious patterns."""
    analyzed = []
    for url in urls:
        flags = []
        risk = 0

        # IP-based URL
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            flags.append('IP-based URL (no domain)')
            risk += 35

        # URL shorteners
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
            'short.link', 'rb.gy', 'cutt.ly', 'is.gd', 'tiny.cc', 'tiny.one',
            'shorte.st', 'adf.ly', 'bc.vc', 'clk.sh', 'reurl.cc',
        ]
        for s in shorteners:
            if s in url.lower():
                flags.append(f'URL shortener ({s}) — hides destination')
                risk += 25
                break

        # Suspicious TLDs
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',    # free/abused
            '.xyz', '.top', '.club', '.work',       # common phish
            '.click', '.link', '.live', '.online',  # click-bait
            '.icu', '.cyou', '.buzz', '.fun',
        ]
        for tld in suspicious_tlds:
            if url.lower().endswith(tld) or f'{tld}/' in url.lower() or f'{tld}?' in url.lower():
                flags.append(f'High-abuse TLD ({tld})')
                risk += 20
                break

        # Lookalike / homograph check
        domain_part = re.search(r'https?://([^/?\s]+)', url)
        domain = domain_part.group(1).lower() if domain_part else ''
        for pattern, brand in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                legit = BRAND_DOMAINS.get(brand, [])
                is_legit = any(domain == ld or domain.endswith('.' + ld) for ld in legit)
                if not is_legit:
                    flags.append(f'Lookalike domain — impersonating {brand}')
                    risk += 45
                    break

        # Punycode / IDN
        if 'xn--' in url.lower():
            flags.append('Punycode/IDN domain — possible homograph attack')
            risk += 40

        # Excessive subdomains (brand.legit.com.evil.com style)
        if domain:
            parts = domain.split('.')
            if len(parts) > 4:
                flags.append(f'Excessive subdomains ({len(parts)} levels)')
                risk += 15
            # Brand name appears as subdomain of unrelated domain
            for brand in BRAND_DOMAINS:
                if brand in parts[:-2] and domain not in BRAND_DOMAINS.get(brand, []):
                    flags.append(f'Brand name "{brand}" used as subdomain of unrelated domain')
                    risk += 30
                    break

        # Credential keywords in URL path
        cred_kw = ['login', 'signin', 'sign-in', 'verify', 'secure', 'account',
                   'password', 'update', 'confirm', 'validate', 'authenticate']
        for kw in cred_kw:
            if kw in url.lower():
                flags.append(f'Credential keyword in URL ({kw})')
                risk += 10
                break

        # Base64-encoded parameters (common in phishing redirect chains)
        if re.search(r'[?&][^=]+=(?:[A-Za-z0-9+/]{20,}={0,2})', url):
            flags.append('Base64-encoded URL parameter')
            risk += 10

        # HTTP (not HTTPS) for credential-looking URLs
        if url.startswith('http://') and any(k in url.lower() for k in ['login', 'secure', 'account', 'verify']):
            flags.append('Credential page served over HTTP (not HTTPS)')
            risk += 15

        analyzed.append({
            'url': url,
            'flags': flags,
            'risk_score': min(risk, 100),
            'risk_level': 'critical' if risk >= 60 else 'high' if risk >= 35 else 'medium' if risk >= 15 else 'low'
        })

    return sorted(analyzed, key=lambda x: x['risk_score'], reverse=True)


def analyze_attachments(msg) -> list:
    """Extract and analyze email attachments."""
    attachments = []
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        
        filename = part.get_filename()
        content_type = part.get_content_type()
        
        if not filename and content_type == 'text/plain':
            continue
        if not filename and content_type == 'text/html':
            continue
        
        if filename:
            filename = decode_str(filename)
            ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            md5 = hashlib.md5(payload).hexdigest() if payload else ''
            sha256 = hashlib.sha256(payload).hexdigest() if payload else ''
            
            risk = 'safe'
            flags = []
            
            if ext in DANGEROUS_EXTENSIONS:
                risk = 'critical'
                flags.append(f'Dangerous file type ({ext})')
            elif ext in SUSPICIOUS_EXTENSIONS:
                risk = 'suspicious'
                flags.append(f'Potentially risky file type ({ext})')
            
            # Double extension trick
            if filename.count('.') > 1:
                parts_name = filename.split('.')
                if parts_name[-2].lower() in ['pdf', 'doc', 'txt', 'jpg', 'png']:
                    flags.append('Double extension (possible disguise)')
                    risk = 'high'
            
            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'size': size,
                'size_human': f'{size/1024:.1f} KB' if size > 1024 else f'{size} B',
                'md5': md5,
                'sha256': sha256,
                'extension': ext,
                'risk': risk,
                'flags': flags
            })
    
    return attachments


def calculate_risk_score(analysis: dict) -> dict:
    """
    Calculate overall phishing risk score — calibrated weights.

    Design goals:
    - A clean legitimate email with no SPF record should score <25 (not trigger PHISHING)
    - A phishing email with valid SPF (attacker's own domain) should still score high
      via brand impersonation + URL flags + keywords
    - SPF/DKIM/DMARC 'fail' vs 'none' treated differently (fail = active failure)
    - Score capped at 100; no single vector should dominate alone
    """
    score = 0
    factors = []

    auth    = analysis.get('auth', {})
    spoof   = analysis.get('spoof_check', {})
    urls    = analysis.get('url_analysis', [])
    attach  = analysis.get('attachments', [])
    brand   = analysis.get('brand_check', {})
    kw      = analysis.get('keyword_analysis', {})
    body    = analysis.get('body', {})

    # ── 1. Email auth failures ───────────────────────────────────────────────
    # 'fail' = active failure (strong signal), 'none' = not configured (weak)
    spf_val   = auth.get('spf', 'none')
    dkim_val  = auth.get('dkim', 'none')
    dmarc_val = auth.get('dmarc', 'none')

    if spf_val in ('fail', 'softfail'):
        pts = 25 if spf_val == 'fail' else 15
        score += pts
        factors.append({'label': f'SPF {spf_val}', 'points': pts, 'severity': 'high'})
    elif spf_val == 'none':
        score += 8
        factors.append({'label': 'SPF not configured', 'points': 8, 'severity': 'low'})

    if dkim_val == 'fail':
        score += 20
        factors.append({'label': 'DKIM signature fail', 'points': 20, 'severity': 'high'})
    elif dkim_val == 'none':
        score += 5
        factors.append({'label': 'DKIM not configured', 'points': 5, 'severity': 'low'})

    if dmarc_val == 'fail':
        score += 20
        factors.append({'label': 'DMARC fail', 'points': 20, 'severity': 'high'})
    elif dmarc_val == 'none':
        score += 5
        factors.append({'label': 'DMARC not configured', 'points': 5, 'severity': 'low'})

    # Bonus: all three auth checks pass → small trust boost (reduce score)
    if spf_val == 'pass' and dkim_val == 'pass' and dmarc_val == 'pass':
        score = max(0, score - 10)

    # ── 2. Display name spoofing ─────────────────────────────────────────────
    if spoof.get('spoofed'):
        score += 25
        factors.append({'label': 'Display name spoofing', 'points': 25, 'severity': 'critical'})

    for issue in spoof.get('issues', []):
        if issue['type'] == 'reply_to_mismatch':
            score += 15
            factors.append({'label': 'Reply-To domain mismatch', 'points': 15, 'severity': 'high'})

    # ── 3. Brand impersonation (NEW) ─────────────────────────────────────────
    brand_findings = brand.get('findings', [])
    brand_pts = 0
    for f in brand_findings:
        if f['severity'] == 'critical' and brand_pts < 40:
            brand_pts += 20
        elif f['severity'] == 'high' and brand_pts < 40:
            brand_pts += 12
    if brand_pts:
        score += brand_pts
        brands = brand.get('impersonated_brands', [])
        label = f'Brand impersonation: {", ".join(brands)}' if brands else 'Brand impersonation detected'
        factors.append({'label': label, 'points': brand_pts, 'severity': 'critical'})

    # IDN/punycode separately
    idn_findings = [f for f in brand_findings if f['type'] == 'punycode_idn']
    if idn_findings:
        score += 15
        factors.append({'label': 'IDN/Punycode domain (homograph attack)', 'points': 15, 'severity': 'high'})

    # ── 4. Suspicious URLs ───────────────────────────────────────────────────
    critical_urls = [u for u in urls if u['risk_level'] == 'critical']
    high_urls     = [u for u in urls if u['risk_level'] == 'high']
    medium_urls   = [u for u in urls if u['risk_level'] == 'medium']

    if critical_urls:
        pts = min(35, 20 + len(critical_urls) * 5)
        score += pts
        factors.append({'label': f'{len(critical_urls)} critical URL(s) detected', 'points': pts, 'severity': 'critical'})
    elif high_urls:
        pts = min(20, 10 + len(high_urls) * 5)
        score += pts
        factors.append({'label': f'{len(high_urls)} high-risk URL(s)', 'points': pts, 'severity': 'high'})
    elif medium_urls:
        score += 8
        factors.append({'label': f'{len(medium_urls)} suspicious URL(s)', 'points': 8, 'severity': 'medium'})

    # ── 5. Dangerous attachments ─────────────────────────────────────────────
    danger_att = [a for a in attach if a['risk'] == 'critical']
    susp_att   = [a for a in attach if a['risk'] in ('suspicious', 'high')]

    if danger_att:
        score += 35
        factors.append({'label': f'{len(danger_att)} dangerous attachment(s)', 'points': 35, 'severity': 'critical'})
    elif susp_att:
        score += 12
        factors.append({'label': f'{len(susp_att)} suspicious attachment(s)', 'points': 12, 'severity': 'medium'})

    # ── 6. Weighted keyword analysis (NEW) ───────────────────────────────────
    kw_score = kw.get('total_score', 0)
    if kw_score > 0:
        kw_cats = kw.get('categories', {})
        hit_cats = list(kw_cats.keys())
        label = f'Phishing keywords ({", ".join(hit_cats[:3])}{"…" if len(hit_cats)>3 else ""})'
        sev = 'high' if kw_score >= 20 else 'medium' if kw_score >= 10 else 'low'
        score += kw_score
        factors.append({'label': label, 'points': kw_score, 'severity': sev})

    # ── 7. HTML-only body (NEW) ───────────────────────────────────────────────
    # Phishing emails often have no text/plain part — only HTML (hides content from scanners)
    has_html = bool(body.get('html', '').strip())
    has_text = bool(body.get('text', '').strip())
    if has_html and not has_text:
        score += 8
        factors.append({'label': 'HTML-only body (no plain text part)', 'points': 8, 'severity': 'low'})

    # ── 8. No Message-ID header (NEW) ─────────────────────────────────────────
    # Legitimate MTAs always add Message-ID; many phishing tools skip it
    headers = analysis.get('headers', {})
    if not headers.get('message_id', '').strip():
        score += 5
        factors.append({'label': 'Missing Message-ID header', 'points': 5, 'severity': 'low'})

    # ── 9. Suspicious sender domain ───────────────────────────────────────────
    from_hdr = analysis.get('headers', {}).get('from', '')
    sender_domain_match = re.search(r'@([\w.\-]+)', from_hdr)
    if sender_domain_match:
        sdomain = sender_domain_match.group(1).lower()
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                           '.click', '.work', '.online', '.icu', '.cyou', '.buzz']
        for tld in suspicious_tlds:
            if sdomain.endswith(tld):
                score += 15
                factors.append({'label': f'Sender domain uses high-abuse TLD ({tld})', 'points': 15, 'severity': 'medium'})
                break

        # Free / public email for business-sounding sender
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                          'aol.com', 'protonmail.com', 'yandex.com', 'mail.com']
        display_m = re.match(r'^"?([^"<]+)"?\s*<', from_hdr)
        display = display_m.group(1).strip().lower() if display_m else ''
        if sdomain in free_providers and any(b in display for b in BRAND_DOMAINS):
            score += 12
            factors.append({'label': f'Brand name in display, but sent from free email provider ({sdomain})',
                            'points': 12, 'severity': 'medium'})

    # ── Final verdict ─────────────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 70:
        verdict = 'PHISHING'
        verdict_color = 'critical'
    elif score >= 45:
        verdict = 'LIKELY PHISHING'
        verdict_color = 'high'
    elif score >= 25:
        verdict = 'SUSPICIOUS'
        verdict_color = 'medium'
    else:
        verdict = 'LIKELY CLEAN'
        verdict_color = 'low'

    return {
        'score': score,
        'verdict': verdict,
        'verdict_color': verdict_color,
        'factors': sorted(factors, key=lambda f: f['points'], reverse=True),
    }


def parse_email(raw: bytes, filename: str = "") -> dict:
    """Main entry point — parse raw email bytes and return full analysis.
    Supports .eml (RFC822) and .msg (Outlook) formats.
    """
    # Auto-detect .msg by filename or magic bytes
    is_msg = (
        filename.lower().endswith('.msg') or
        raw[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # OLE2 magic
    )
    if is_msg:
        try:
            raw = msg_to_eml(raw)
        except Exception as e:
            # Fall through to try parsing as-is
            pass

    msg = email.message_from_bytes(raw, policy=policy.compat32)
    
    # ── Basic Headers ──────────────────────────────────────────────────────────
    from_header = decode_str(msg.get('From', ''))
    to_header = decode_str(msg.get('To', ''))
    cc_header = decode_str(msg.get('Cc', ''))
    reply_to = decode_str(msg.get('Reply-To', ''))
    subject = decode_str(msg.get('Subject', ''))
    date_str = decode_str(msg.get('Date', ''))
    message_id = decode_str(msg.get('Message-ID', ''))
    x_mailer = decode_str(msg.get('X-Mailer', '') or msg.get('User-Agent', ''))
    x_originating_ip = decode_str(msg.get('X-Originating-IP', '') or msg.get('X-Sender-IP', ''))
    
    # ── Body Extraction ────────────────────────────────────────────────────────
    body_text = ''
    body_html = ''
    
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    body_text += payload.decode(charset, errors='replace')
            elif ct == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    body_html += payload.decode(charset, errors='replace')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            ct = msg.get_content_type()
            if ct == 'text/html':
                body_html = payload.decode(charset, errors='replace')
            else:
                body_text = payload.decode(charset, errors='replace')
    
    # Strip HTML for text analysis
    html_stripped = re.sub(r'<[^>]+>', ' ', body_html)
    full_text = body_text + ' ' + html_stripped
    
    # ── IOC Extraction ─────────────────────────────────────────────────────────
    iocs = extract_iocs(full_text + ' ' + from_header + ' ' + to_header)
    
    # ── Auth Analysis ──────────────────────────────────────────────────────────
    auth = check_auth_headers(msg)
    
    # ── Received Chain ─────────────────────────────────────────────────────────
    hops = analyze_received_chain(msg)
    
    # ── Spoof Check ────────────────────────────────────────────────────────────
    spoof = check_display_name_spoof(from_header, reply_to)
    
    # ── URL Analysis ───────────────────────────────────────────────────────────
    url_analysis = analyze_urls(iocs['urls'])
    
    # ── Attachments ────────────────────────────────────────────────────────────
    attachments = analyze_attachments(msg)
    
    # ── Keyword Check ──────────────────────────────────────────────────────────
    keywords = check_keywords(full_text + ' ' + subject)
    keyword_analysis = check_keywords_weighted(full_text + ' ' + subject)

    # ── Brand Impersonation Check (NEW) ────────────────────────────────────────
    brand_check = check_brand_impersonation(
        from_header, subject, full_text, iocs['urls']
    )

    # ── All raw headers ────────────────────────────────────────────────────────
    raw_headers = []
    for key, val in msg.items():
        raw_headers.append({'key': key, 'value': decode_str(val)})

    analysis = {
        'headers': {
            'from': from_header,
            'to': to_header,
            'cc': cc_header,
            'reply_to': reply_to,
            'subject': subject,
            'date': date_str,
            'message_id': message_id,
            'x_mailer': x_mailer,
            'x_originating_ip': x_originating_ip,
        },
        'auth': auth,
        'received_chain': hops,
        'spoof_check': spoof,
        'brand_check': brand_check,
        'iocs': iocs,
        'url_analysis': url_analysis,
        'attachments': attachments,
        'phish_keywords': keywords,
        'keyword_analysis': keyword_analysis,
        'body': {
            'text': body_text[:5000],
            'html': body_html[:10000],
        },
        'raw_headers': raw_headers,
    }
    
    # ── Risk Score ─────────────────────────────────────────────────────────────
    analysis['risk'] = calculate_risk_score(analysis)
    
    return analysis
