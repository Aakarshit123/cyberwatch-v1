from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import re
from tools.upi_analyzer import analyze_upi_graph
from tools.whatsapp_analyzer import analyze_whatsapp_chat

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upi')
def upi_tool():
    return render_template('upi.html')

@app.route('/whatsapp')
def whatsapp_tool():
    return render_template('whatsapp.html')

@app.route('/api/analyze-upi', methods=['POST'])
def analyze_upi():
    try:
        data = request.get_json()
        transactions = data.get('transactions', [])
        if not transactions:
            return jsonify({'error': 'No transaction data provided'}), 400
        result = analyze_upi_graph(transactions)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-whatsapp', methods=['POST'])
def analyze_whatsapp():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        content = file.read().decode('utf-8', errors='ignore')
        result = analyze_whatsapp_chat(content)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sample-upi')
def sample_upi():
    """Return sample UPI transaction data for demo"""
    sample = [
        {"from": "9876543210@paytm", "to": "mule001@ybl", "amount": 15000, "date": "2026-06-01"},
        {"from": "victim1@okaxis", "to": "9876543210@paytm", "amount": 50000, "date": "2026-06-01"},
        {"from": "victim2@okicici", "to": "9876543210@paytm", "amount": 30000, "date": "2026-06-02"},
        {"from": "victim3@okhdfcbank", "to": "9876543210@paytm", "amount": 20000, "date": "2026-06-02"},
        {"from": "9876543210@paytm", "to": "mule002@okaxis", "amount": 25000, "date": "2026-06-03"},
        {"from": "mule001@ybl", "to": "mastermind@apl", "amount": 14000, "date": "2026-06-03"},
        {"from": "mule002@okaxis", "to": "mastermind@apl", "amount": 24000, "date": "2026-06-04"},
        {"from": "victim4@ybl", "to": "9876543210@paytm", "amount": 10000, "date": "2026-06-04"},
        {"from": "victim5@paytm", "to": "scammer2@okaxis", "amount": 8000, "date": "2026-06-05"},
        {"from": "scammer2@okaxis", "to": "mastermind@apl", "amount": 7500, "date": "2026-06-05"},
    ]
    return jsonify(sample)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
