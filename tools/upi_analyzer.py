from collections import defaultdict
from datetime import datetime

def analyze_upi_graph(transactions):
    """
    Analyze UPI transactions to detect fraud patterns.
    Returns graph data + flagged suspicious nodes.
    """
    nodes = {}
    edges = []
    in_degree = defaultdict(float)   # total money received
    out_degree = defaultdict(float)  # total money sent
    in_count = defaultdict(int)      # number of senders
    out_count = defaultdict(int)     # number of receivers
    
    all_ids = set()

    for tx in transactions:
        frm = tx.get('from', '').strip()
        to = tx.get('to', '').strip()
        amount = float(tx.get('amount', 0))
        date = tx.get('date', '')

        if not frm or not to:
            continue

        all_ids.add(frm)
        all_ids.add(to)

        in_degree[to] += amount
        out_degree[frm] += amount
        in_count[to] += 1
        out_count[frm] += 1

        edges.append({
            'from': frm,
            'to': to,
            'amount': amount,
            'date': date,
            'label': f'₹{amount:,.0f}'
        })

    # Build node list with risk scoring
    suspicious_nodes = []
    for uid in all_ids:
        received = in_degree[uid]
        sent = out_degree[uid]
        senders = in_count[uid]
        receivers = out_count[uid]

        # Risk scoring logic
        risk_score = 0
        risk_reasons = []

        # Mule account pattern: receives from many, sends to few
        if senders >= 3 and receivers <= 2:
            risk_score += 40
            risk_reasons.append(f"Receives from {senders} sources, sends to {receivers}")

        # High throughput (money flows through quickly)
        if received > 0 and sent > 0:
            ratio = min(sent, received) / max(sent, received)
            if ratio > 0.7:
                risk_score += 30
                risk_reasons.append("High pass-through ratio (likely mule)")

        # Large amounts
        if received > 50000:
            risk_score += 20
            risk_reasons.append(f"Large total received: ₹{received:,.0f}")

        # Central hub (many connections)
        total_connections = senders + receivers
        if total_connections >= 5:
            risk_score += 20
            risk_reasons.append(f"High connectivity ({total_connections} connections)")

        # Determine node type/role
        if received == 0 and sent > 0:
            role = 'victim'
            color = '#4CAF50'
        elif sent == 0 and received > 0:
            role = 'sink'
            color = '#9C27B0'
        elif risk_score >= 60:
            role = 'mastermind'
            color = '#F44336'
        elif risk_score >= 30:
            role = 'mule'
            color = '#FF9800'
        else:
            role = 'unknown'
            color = '#2196F3'

        node_data = {
            'id': uid,
            'label': uid,
            'role': role,
            'color': color,
            'received': received,
            'sent': sent,
            'risk_score': min(risk_score, 100),
            'risk_reasons': risk_reasons,
            'in_connections': senders,
            'out_connections': receivers,
            'size': max(20, min(60, 15 + total_connections * 5))
        }

        nodes[uid] = node_data

        if risk_score >= 30:
            suspicious_nodes.append({
                'id': uid,
                'role': role,
                'risk_score': min(risk_score, 100),
                'reasons': risk_reasons,
                'total_received': received,
                'total_sent': sent
            })

    # Sort suspicious by risk score
    suspicious_nodes.sort(key=lambda x: x['risk_score'], reverse=True)

    # Summary stats
    total_amount = sum(e['amount'] for e in edges)
    summary = {
        'total_transactions': len(edges),
        'total_amount': total_amount,
        'unique_accounts': len(all_ids),
        'suspicious_accounts': len(suspicious_nodes),
        'victims': sum(1 for n in nodes.values() if n['role'] == 'victim'),
        'mules': sum(1 for n in nodes.values() if n['role'] == 'mule'),
        'masterminds': sum(1 for n in nodes.values() if n['role'] == 'mastermind'),
    }

    return {
        'nodes': list(nodes.values()),
        'edges': edges,
        'suspicious': suspicious_nodes,
        'summary': summary
    }
