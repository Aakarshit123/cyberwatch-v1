import re
from collections import defaultdict
from datetime import datetime

# WhatsApp export format patterns (handles both 12hr and 24hr, Indian format)
PATTERNS = [
    # DD/MM/YYYY, HH:MM - Name: message  (24hr)
    r'(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?)\s*-\s*([^:]+?):\s*(.*)',
    # DD/MM/YYYY, HH:MM AM/PM - Name: message  (12hr)
    r'(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}\s*[APap][Mm])\s*-\s*([^:]+?):\s*(.*)',
    # [DD/MM/YYYY, HH:MM:SS] Name: message
    r'\[(\d{1,2}/\d{1,2}/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?)\]\s+([^:]+?):\s*(.*)',
]

SCAM_KEYWORDS = [
    'lottery', 'prize', 'winner', 'claim', 'reward', 'free', 'click here',
    'bit.ly', 'tinyurl', 'loan', 'offer', 'limited', 'urgent', 'otp',
    'bank account', 'kyc', 'verify', 'update your', 'blocked', 'suspended',
    'income tax', 'refund', 'cashback', 'earn money', 'work from home',
    'investment', 'profit', 'double', 'crypto', 'bitcoin', 'job offer',
    'congratulations', 'selected', 'call now', 'whatsapp', 'forward this',
    'share this', 'upi', 'paytm', 'phonepay', 'googlepay', 'send money'
]

URL_PATTERN = re.compile(r'https?://\S+|www\.\S+|bit\.ly/\S+|t\.me/\S+')
FORWARD_PATTERN = re.compile(r'<This message was forwarded>', re.IGNORECASE)
FORWARDED_MANY = re.compile(r'Forwarded many times', re.IGNORECASE)
PHONE_PATTERN = re.compile(r'\b[6-9]\d{9}\b|\+91\s?\d{10}|\+\d{10,13}')
UPI_PATTERN = re.compile(r'[\w.\-]+@(paytm|ybl|okaxis|okicici|okhdfcbank|apl|ibl|upi|oksbi)', re.IGNORECASE)


def parse_whatsapp(content):
    messages = []
    lines = content.split('\n')
    current_msg = None

    for line in lines:
        matched = False
        for pattern in PATTERNS:
            m = re.match(pattern, line)
            if m:
                if current_msg:
                    messages.append(current_msg)
                date_str, time_str, sender, text = m.groups()
                sender = sender.strip()
                current_msg = {
                    'date': date_str.strip(),
                    'time': time_str.strip(),
                    'sender': sender,
                    'text': text.strip(),
                    'forwarded': bool(FORWARD_PATTERN.search(text)),
                    'forwarded_many': bool(FORWARDED_MANY.search(text)),
                }
                matched = True
                break
        if not matched and current_msg:
            # continuation of previous message
            current_msg['text'] += ' ' + line.strip()

    if current_msg:
        messages.append(current_msg)

    return messages


def analyze_whatsapp_chat(content):
    messages = parse_whatsapp(content)

    if not messages:
        return {'error': 'Could not parse WhatsApp chat. Make sure it is an exported .txt file.'}

    # Per-sender stats
    sender_stats = defaultdict(lambda: {
        'count': 0,
        'forwarded': 0,
        'forwarded_many': 0,
        'urls': [],
        'phones': [],
        'upi_ids': [],
        'scam_hits': 0,
        'scam_messages': [],
        'messages': []
    })

    # Timeline
    date_activity = defaultdict(int)
    forwarded_timeline = defaultdict(int)

    all_urls = []
    all_phones = set()
    all_upi = set()
    total_forwarded = 0
    total_scam = 0

    for msg in messages:
        sender = msg['sender']
        text = msg['text']
        date = msg['date']

        s = sender_stats[sender]
        s['count'] += 1
        s['messages'].append({'date': date, 'time': msg['time'], 'text': text[:200]})

        date_activity[date] += 1

        if msg['forwarded'] or msg['forwarded_many']:
            s['forwarded'] += 1
            forwarded_timeline[date] += 1
            total_forwarded += 1
        if msg['forwarded_many']:
            s['forwarded_many'] += 1

        # Extract IOCs
        urls = URL_PATTERN.findall(text)
        phones = PHONE_PATTERN.findall(text)
        upis = UPI_PATTERN.findall(text)

        s['urls'].extend(urls)
        s['phones'].extend(phones)
        all_urls.extend(urls)
        all_phones.update(phones)
        all_upi.update(upis)

        # Scam keyword scoring
        text_lower = text.lower()
        hits = [kw for kw in SCAM_KEYWORDS if kw in text_lower]
        if hits:
            s['scam_hits'] += len(hits)
            s['scam_messages'].append({
                'date': date,
                'text': text[:300],
                'keywords': hits
            })
            total_scam += 1

    # Risk scoring per sender
    flagged_senders = []
    sender_list = []
    for sender, s in sender_stats.items():
        risk = 0
        risk_reasons = []

        fwd_ratio = s['forwarded'] / s['count'] if s['count'] > 0 else 0
        if fwd_ratio > 0.5:
            risk += 30
            risk_reasons.append(f"High forward ratio: {fwd_ratio:.0%}")
        if s['forwarded_many'] > 0:
            risk += 25
            risk_reasons.append(f"{s['forwarded_many']} 'Forwarded many times' messages")
        if s['scam_hits'] > 3:
            risk += 30
            risk_reasons.append(f"Scam keywords found: {s['scam_hits']} hits")
        if s['urls']:
            risk += 10
            risk_reasons.append(f"Shared {len(s['urls'])} URLs")

        sender_data = {
            'name': sender,
            'total_messages': s['count'],
            'forwarded': s['forwarded'],
            'forwarded_many': s['forwarded_many'],
            'forward_ratio': round(fwd_ratio, 2),
            'scam_hits': s['scam_hits'],
            'urls_shared': list(set(s['urls']))[:10],
            'scam_messages': s['scam_messages'][:5],
            'risk_score': min(risk, 100),
            'risk_reasons': risk_reasons,
        }
        sender_list.append(sender_data)
        if risk >= 25:
            flagged_senders.append(sender_data)

    flagged_senders.sort(key=lambda x: x['risk_score'], reverse=True)
    sender_list.sort(key=lambda x: x['total_messages'], reverse=True)

    # Build timeline data
    dates_sorted = sorted(date_activity.keys())
    timeline = [{'date': d, 'messages': date_activity[d], 'forwarded': forwarded_timeline[d]} for d in dates_sorted]

    summary = {
        'total_messages': len(messages),
        'total_senders': len(sender_stats),
        'total_forwarded': total_forwarded,
        'total_scam_flagged': total_scam,
        'unique_urls': len(set(all_urls)),
        'unique_phones': len(all_phones),
        'unique_upi': len(all_upi),
        'flagged_senders': len(flagged_senders),
        'date_range': f"{dates_sorted[0]} to {dates_sorted[-1]}" if dates_sorted else 'N/A'
    }

    return {
        'summary': summary,
        'timeline': timeline,
        'senders': sender_list[:20],
        'flagged': flagged_senders,
        'iocs': {
            'urls': list(set(all_urls))[:30],
            'phones': list(all_phones)[:30],
            'upi_ids': list(all_upi)[:30],
        }
    }
