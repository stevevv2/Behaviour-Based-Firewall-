# dashboard.py

from flask import Flask, request, jsonify, render_template
from datetime import datetime

app = Flask(__name__)
logs = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/log', methods=['POST'])
def log_data():
    data = request.get_json()
    if data:
        log_entry = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "switch_id": data.get("switch_id", "N/A"),
            "anomaly": data.get("anomaly", "NO"),
            # <<< THIS IS THE UPDATED LINE >>>
            "attack_type": data.get("attack_type", "Normal Traffic"), 
            "action": data.get("action", "ALLOW"),
            "features": data.get("features", []) 
        }
        
        logs.insert(0, log_entry)
        
        if len(logs) > 200:
            logs.pop()
    
    return jsonify({"status": "success", "message": "Log received"}), 201

@app.route('/get_logs')
def get_logs():
    return jsonify(logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
