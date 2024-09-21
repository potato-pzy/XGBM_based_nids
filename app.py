from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from scapy.all import *
from collections import defaultdict, deque
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import subprocess
import json
import threading
import time
import requests

from networkdata import process_packet, data, preprocess_data, select_features, scale_features, load_model, classify_malicious_ips

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ip_database.db'
db = SQLAlchemy(app)

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)

class AllowedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)

with app.app_context():
    db.create_all()

# Global variables to store results
latest_results = []
is_capturing = False
malicious_ip_detected = False

def check_ip_with_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def capture_and_process():
    global latest_results, is_capturing, malicious_ip_detected
    api_key = "77d9d553fa54fc85f938f8ee379abbc4e220e89c711b0b3f9f41b6ceb65eb567"
    while True:
        if is_capturing:
            print("Starting packet capture...")
            filter_expr = "ip and not src net 192.168.1.0/24"
            try:
                packets = sniff(prn=process_packet, filter=filter_expr, count=10, timeout=30)
                print(f"Captured {len(packets)} packets")
            except Exception as e:
                print(f"Error during packet capture: {e}")
                continue

            if not data:
                print("No packet data collected. Skipping processing.")
                continue

            df = pd.DataFrame(data)
            original_ips = df['src_ip'].copy()

            df_preprocessed = preprocess_data(df)
            df_selected_features = select_features(df_preprocessed, [])
            df_scaled = scale_features(df_selected_features)

            loaded_model = load_model()
            malicious_results = classify_malicious_ips(df_scaled, loaded_model, original_ips)

            for index, row in malicious_results.iterrows():
                ip_address = row['IP Address']
                vt_result = check_ip_with_virustotal(ip_address, api_key)
                if vt_result:
                    last_analysis_stats = vt_result['data']['attributes']['last_analysis_stats']
                    if last_analysis_stats['suspicious'] > 1 or last_analysis_stats['harmless'] < 30:
                        latest_results.append(row.to_dict())
                        malicious_ip_detected = True
                        print(f"Malicious IP detected and confirmed by VirusTotal: {ip_address}")

            # Clear data for next iteration
            data.clear()
        time.sleep(5)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/blocked_ips')
def blocked_ips():
    return render_template('blocked_ips.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global is_capturing
    is_capturing = True
    return jsonify({"status": "Capture started"})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({"status": "Capture stopped"})

@app.route('/reset_detection', methods=['POST'])
def reset_detection():
    global malicious_ip_detected, latest_results
    malicious_ip_detected = False
    latest_results = []
    return jsonify({"status": "Detection reset. You can start capture again."})

@app.route('/get_results')
def get_results():
    blocked_ips = [ip.ip_address for ip in BlockedIP.query.all()]
    allowed_ips = [ip.ip_address for ip in AllowedIP.query.all()]
    filtered_results = [result for result in latest_results if result['IP Address'] not in blocked_ips and result['IP Address'] not in allowed_ips]
    return jsonify(filtered_results)

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json['ip']
    try:
        blocked_ip = BlockedIP(ip_address=ip)
        db.session.add(blocked_ip)
        db.session.commit()
        print(f"Successfully blocked IP: {ip}")

        # Block the IP using netsh (Windows-specific, adjust for other OS if needed)
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=BlockIP', 'dir=in', 'action=block', 'remoteip=' + ip], check=True)
            print(f"IP {ip} blocked at the firewall level")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip} at firewall level: {e}")
            return jsonify({"error": f"Failed to block IP {ip} at firewall level", "success": False}), 500

        # Remove the IP from latest_results
        global latest_results
        latest_results = [result for result in latest_results if result['IP Address'] != ip]

        return jsonify({"status": f"IP {ip} blocked successfully", "success": True})
    except Exception as e:
        print(f"Error blocking IP {ip}: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Failed to block IP {ip}", "success": False}), 500
    

@app.route('/allow_ip', methods=['POST'])
def allow_ip():
    ip = request.json['ip']
    try:
        allowed_ip = AllowedIP(ip_address=ip)
        db.session.add(allowed_ip)
        db.session.commit()
        print(f"Successfully allowed IP: {ip}")

        # Remove the IP from the blocked list if it was previously blocked
        blocked_ip = BlockedIP.query.filter_by(ip_address=ip).first()
        if blocked_ip:
            db.session.delete(blocked_ip)
            db.session.commit()
            
            # Remove the firewall rule (Windows-specific, adjust for other OS if needed)
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=BlockIP', 'remoteip=' + ip], check=True)
                print(f"IP {ip} unblocked at the firewall level")
            except subprocess.CalledProcessError as e:
                print(f"Error unblocking IP {ip} at firewall level: {e}")

        return jsonify({"status": f"IP {ip} allowed successfully"})
    except Exception as e:
        print(f"Error allowing IP {ip}: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Failed to allow IP {ip}"}), 500

@app.route('/inspect_ip', methods=['POST'])
def inspect_ip():
    ip = request.json['ip']
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": "Failed to fetch IP information"}), 500
    except Exception as e:
        print(f"Error inspecting IP {ip}: {str(e)}")
        return jsonify({"error": f"Failed to inspect IP {ip}"}), 500

@app.route('/get_blocked_ips')
def get_blocked_ips():
    try:
        blocked_ips = BlockedIP.query.all()
        return jsonify([ip.ip_address for ip in blocked_ips])
    except Exception as e:
        print(f"Error in get_blocked_ips: {str(e)}")
        return jsonify({"error": "Failed to retrieve blocked IPs"}), 500

@app.route('/get_allowed_ips')
def get_allowed_ips():
    try:
        allowed_ips = AllowedIP.query.all()
        return jsonify([ip.ip_address for ip in allowed_ips])
    except Exception as e:
        print(f"Error in get_allowed_ips: {str(e)}")
        return jsonify({"error": "Failed to retrieve allowed IPs"}), 500

if __name__ == "__main__":
    capture_thread = threading.Thread(target=capture_and_process)
    capture_thread.start()
    app.run(debug=True, use_reloader=False)