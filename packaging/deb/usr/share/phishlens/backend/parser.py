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

# Suspicious keywords in subject/body
PHISH_KEYWORDS = [
    'verify your account', 'confirm your identity', 'unusual activity',
    'suspended', 'limited', 'unauthorized', 'click here', 'login now',
    'update your information', 'your account has been', 'action required',
    'urgent', 'immediate action', 'password expired', 'security alert',
    'won', 'winner', 'prize', 'lottery', 'free gift', 'congratulations',
    'bank account', 'credit card', 'ssn', 'social security', 'wire transfer',
    'nigerian', 'inheritance', 'beneficiary', 'million dollars',
    'reset your password', 'verify now', 'click below', 'dear customer',
    'dear user', 'dear valued'
]

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
    """Check for phishing keywords."""
    text_lower = text.lower()
    found = []
    for kw in PHISH_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return found


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
    
    # Extract display name and actual email
    display_match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>', from_header)
    if display_match:
        display_name = display_match.group(1).strip()
        actual_email = display_match.group(2).strip()
        
        # Check if display name contains a different domain than actual
        display_domain_match = re.search(r'@([\w.]+)', display_name)
        actual_domain_match = re.search(r'@([\w.]+)', actual_email)
        
        if display_domain_match and actual_domain_match:
            if display_domain_match.group(1).lower() != actual_domain_match.group(1).lower():
                issues.append({
                    'type': 'domain_mismatch',
                    'detail': f'Display shows @{display_domain_match.group(1)} but sent from @{actual_domain_match.group(1)}'
                })
        
        # Reply-to mismatch
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
            'email': display_match.group(2).strip() if display_match else from_header
        }
    }


def analyze_urls(urls: list) -> list:
    """Analyze URLs for suspicious patterns."""
    analyzed = []
    for url in urls:
        flags = []
        risk = 0
        
        # IP-based URL
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            flags.append('IP-based URL')
            risk += 30
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 
                      'short.link', 'rb.gy', 'cutt.ly', 'is.gd', 'tiny.cc']
        for s in shorteners:
            if s in url.lower():
                flags.append(f'URL shortener ({s})')
                risk += 25
                break
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.click']
        for tld in suspicious_tlds:
            if url.lower().endswith(tld) or f'{tld}/' in url.lower():
                flags.append(f'Suspicious TLD ({tld})')
                risk += 20
                break
        
        # Homograph / lookalike
        lookalikes = {'paypa1': 'paypal', 'g00gle': 'google', 'arnazon': 'amazon',
                      'micros0ft': 'microsoft', 'app1e': 'apple', 'faceb00k': 'facebook'}
        for fake, real in lookalikes.items():
            if fake in url.lower():
                flags.append(f'Lookalike domain (impersonating {real})')
                risk += 40
        
        # Excessive subdomains
        domain_part = re.search(r'https?://([^/]+)', url)
        if domain_part:
            parts = domain_part.group(1).split('.')
            if len(parts) > 4:
                flags.append(f'Excessive subdomains ({len(parts)} levels)')
                risk += 15
        
        # Login/credential keywords in URL
        cred_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'update', 'confirm']
        for kw in cred_keywords:
            if kw in url.lower():
                flags.append(f'Credential keyword in URL ({kw})')
                risk += 10
                break
        
        # Base64 or encoded params
        if re.search(r'[?&][^=]+=(?:[A-Za-z0-9+/]{20,}={0,2})', url):
            flags.append('Base64-encoded parameter')
            risk += 10
        
        analyzed.append({
            'url': url,
            'flags': flags,
            'risk_score': min(risk, 100),
            'risk_level': 'critical' if risk >= 60 else 'high' if risk >= 40 else 'medium' if risk >= 20 else 'low'
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
    """Calculate overall phishing risk score."""
    score = 0
    factors = []
    
    auth = analysis.get('auth', {})
    
    # Auth failures
    if auth.get('spf') in ['fail', 'softfail']:
        score += 25
        factors.append({'label': 'SPF fail', 'points': 25, 'severity': 'high'})
    elif auth.get('spf') == 'none':
        score += 10
        factors.append({'label': 'No SPF record', 'points': 10, 'severity': 'medium'})
    
    if auth.get('dkim') in ['fail', 'none']:
        score += 20
        factors.append({'label': f'DKIM {auth.get("dkim")}', 'points': 20, 'severity': 'high'})
    
    if auth.get('dmarc') in ['fail', 'none']:
        score += 20
        factors.append({'label': f'DMARC {auth.get("dmarc")}', 'points': 20, 'severity': 'high'})
    
    # Display name spoofing
    spoof = analysis.get('spoof_check', {})
    if spoof.get('spoofed'):
        score += 30
        factors.append({'label': 'Display name spoofing detected', 'points': 30, 'severity': 'critical'})
    
    # Reply-to mismatch
    for issue in spoof.get('issues', []):
        if issue['type'] == 'reply_to_mismatch':
            score += 20
            factors.append({'label': 'Reply-To domain mismatch', 'points': 20, 'severity': 'high'})
    
    # Suspicious URLs
    urls = analysis.get('url_analysis', [])
    critical_urls = [u for u in urls if u['risk_level'] == 'critical']
    high_urls = [u for u in urls if u['risk_level'] == 'high']
    if critical_urls:
        score += 30
        factors.append({'label': f'{len(critical_urls)} critical URL(s)', 'points': 30, 'severity': 'critical'})
    elif high_urls:
        score += 15
        factors.append({'label': f'{len(high_urls)} high-risk URL(s)', 'points': 15, 'severity': 'high'})
    
    # Dangerous attachments
    attachments = analysis.get('attachments', [])
    danger_att = [a for a in attachments if a['risk'] == 'critical']
    susp_att = [a for a in attachments if a['risk'] in ['suspicious', 'high']]
    if danger_att:
        score += 35
        factors.append({'label': f'{len(danger_att)} dangerous attachment(s)', 'points': 35, 'severity': 'critical'})
    elif susp_att:
        score += 15
        factors.append({'label': f'{len(susp_att)} suspicious attachment(s)', 'points': 15, 'severity': 'medium'})
    
    # Phishing keywords
    keywords = analysis.get('phish_keywords', [])
    if len(keywords) >= 3:
        score += 20
        factors.append({'label': f'{len(keywords)} phishing keywords found', 'points': 20, 'severity': 'medium'})
    elif keywords:
        score += 10
        factors.append({'label': f'{len(keywords)} phishing keyword(s) found', 'points': 10, 'severity': 'low'})
    
    score = min(score, 100)
    
    if score >= 75:
        verdict = 'PHISHING'
        verdict_color = 'critical'
    elif score >= 50:
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
        'factors': factors
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
        'iocs': iocs,
        'url_analysis': url_analysis,
        'attachments': attachments,
        'phish_keywords': keywords,
        'body': {
            'text': body_text[:5000],
            'html': body_html[:10000],
        },
        'raw_headers': raw_headers,
    }
    
    # ── Risk Score ─────────────────────────────────────────────────────────────
    analysis['risk'] = calculate_risk_score(analysis)
    
    return analysis
