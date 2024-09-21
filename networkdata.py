from scapy.all import *
from collections import defaultdict, deque
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
import joblib
import ipaddress
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, accuracy_score
from tabulate import tabulate
import json
# Initialize defaultdicts for various features

login_attempts = defaultdict(int)
successful_logins = set()
compromised_ips = set()
root_shell_attempts = defaultdict(int)
su_attempts = defaultdict(int)
packet_count = defaultdict(int)
file_creations = defaultdict(int)
shell_activities = defaultdict(int)
access_files = defaultdict(int)
outbound_cmds = defaultdict(int)
host_login_attempts = defaultdict(int)
guest_login_attempts = defaultdict(int)
root_activities = defaultdict(int)


# Additional variables for new features
connection_history = defaultdict(lambda: deque(maxlen=100))   
syn_errors = defaultdict(int)
rej_errors = defaultdict(int)

# Constants for threshold tuning
MAX_PACKET_RATE = 100   
MAX_CONNECTIONS = 50    
MAX_ERROR_RATE = 0.2    
data = []
results=[]
Columns: []
Index: []

exclusion_list = {"96.51.46.69","85.148.225.143","192.168.1.7","116.230.73.77","68.35.243.220","177.189.201.22","84.71.63.62 ","86.99.178.49"}

def get_feature_importances(model, feature_names):
    importances = model.feature_importances_
    feature_importances = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    return feature_importances

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False
 
# Function to handle incoming packets
def process_packet(packet):
  # Extracting IP layer information
  ddos=0
  syn=0
  if IP in packet:
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
        
    if src_ip in exclusion_list or not is_public_ip(src_ip):
            return
         
        # Extracting TCP layer information
    if TCP in packet:
            duration = packet.time
            protocol_type = 'TCP'
            service = packet[TCP].dport
            flags = packet[TCP].flags
            land_flag = (src_ip == dst_ip and packet[TCP].sport == packet[TCP].dport)
            wrong_fragment = (packet[IP].frag > 0)
            urgent = (flags & 0x20) != 0   
            hot = 0   
 
            if packet.haslayer(Raw):   
                src_bytes = len(packet[Raw].load)
                dst_bytes = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4 - len(packet[Raw].load)
            else:
                src_bytes = 0
                dst_bytes = 0

            # Failed logins
            if b"failed" in bytes(packet[TCP].payload).lower():
                login_attempts[src_ip] += 1

            # Successful logins
            if b"login successful" in bytes(packet[TCP].payload).lower():
                successful_logins.add(src_ip)

            num_failed_logins = login_attempts[src_ip]
            logged_in = 1 if src_ip in successful_logins else 0

            # Compromised IP detection  
            if b"compromised" in bytes(packet[TCP].payload).lower():
                compromised_ips.add(src_ip)

            num_compromised = len(compromised_ips)

            # Root shell attempts 
            if b"root shell" in bytes(packet[TCP].payload).lower():
                root_shell_attempts[src_ip] += 1

            root_shell = root_shell_attempts[src_ip]

            # su attempted 
            if b"su attempted" in bytes(packet[TCP].payload).lower():
                su_attempts[src_ip] += 1

            su_attempted = su_attempts[src_ip]

            # Root activity detection 
            if b"root activity" in bytes(packet[TCP].payload).lower():
                root_activities[src_ip] += 1

            num_root = root_activities[src_ip]

            # File creation detection  
            if b"file created" in bytes(packet[TCP].payload).lower():
                file_creations[src_ip] += 1

            # Example logic for file access events
            if b"file accessed" in bytes(packet[TCP].payload).lower():
                access_files[src_ip] += 1

            # Shell activity detection  
            if b"shell activity" in bytes(packet[TCP].payload).lower():
                shell_activities[src_ip] += 1

            num_shells = shell_activities[src_ip]

            # Access file detection  
            if b"file accessed" in bytes(packet[TCP].payload).lower():
                access_files[src_ip] += 1

            num_access_files = access_files[src_ip]

            # Outbound command detection (Example: based on specific patterns)
            if b"outbound cmd" in bytes(packet[TCP].payload).lower():
                outbound_cmds[src_ip] += 1

            num_outbound_cmds = outbound_cmds[src_ip]

            # Host login detection (Example: based on specific patterns)
            if b"host login" in bytes(packet[TCP].payload).lower():
                host_login_attempts[src_ip] += 1

            is_host_login = host_login_attempts[src_ip]

            # Guest login detection (Example: based on specific patterns)
            if b"guest login" in bytes(packet[TCP].payload).lower():
                guest_login_attempts[src_ip] += 1

            is_guest_login = guest_login_attempts[src_ip]
            # Example logic for outbound command attempts
            if b"outbound cmd" in bytes(packet[TCP].payload).lower():
                outbound_cmds[src_ip] += 1

            # Example logic for host login attempts
            if b"host login" in bytes(packet[TCP].payload).lower():
                host_login_attempts[src_ip] += 1

            # Example logic for guest login attempts
            if b"guest login" in bytes(packet[TCP].payload).lower():
                guest_login_attempts[src_ip] += 1

            # Example logic for root activity detection
            if b"root activity" in bytes(packet[TCP].payload).lower():
                root_activities[src_ip] += 1

            # Update packet count for this source IP
            packet_count[src_ip] += 1

            # Connection history for additional features
            connection_history[src_ip].append((dst_ip, service, flags))
            recent_connections = list(connection_history[src_ip])
            srv_count = sum(1 for conn in recent_connections if conn[1] == service)
            same_srv_rate = srv_count / len(recent_connections) if recent_connections else 0
            diff_srv_rate = 1 - same_srv_rate

            dst_host_count = sum(1 for conn in recent_connections if conn[0] == dst_ip)
            dst_host_srv_count = sum(1 for conn in recent_connections if conn[0] == dst_ip and conn[1] == service)
            dst_host_same_srv_rate = dst_host_srv_count / dst_host_count if dst_host_count else 0
            dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
            dst_host_same_src_port_rate = sum(1 for conn in recent_connections if conn[1] == service) / len(recent_connections) if recent_connections else 0
            dst_host_srv_diff_host_rate = sum(1 for conn in recent_connections if conn[0] != dst_ip and conn[1] == service) / len(recent_connections) if recent_connections else 0

            # Error rates
            serror_rate = sum(1 for conn in recent_connections if "S" in conn[2]) / len(recent_connections) if recent_connections else 0
            srv_serror_rate = sum(1 for conn in recent_connections if "S" in conn[2] and conn[1] == service) / srv_count if srv_count else 0
            rerror_rate = sum(1 for conn in recent_connections if "R" in conn[2]) / len(recent_connections) if recent_connections else 0
            srv_rerror_rate = sum(1 for conn in recent_connections if "R" in conn[2] and conn[1] == service) / srv_count if srv_count else 0

       
            if len(recent_connections) > 1:
                for i in range(len(recent_connections) - 1):
                    if recent_connections[i][0] == recent_connections[i + 1][0]:
                        #print(f"Potential SYN flood detected from {src_ip}: Consistent connection attempts to {recent_connections[i][0]}")
                        syn+=1
            # Example: Anomaly detection based on error rates
            if (serror_rate + rerror_rate) > MAX_ERROR_RATE:
                #print(f"Potential DDoS detected from {src_ip}: High error rate ({(serror_rate + rerror_rate)*100:.2f}%)")
                ddos+=1
            # Example: Signature-based detection (hypothetical example)
            suspicious_patterns = [b"attack_pattern1", b"attack_pattern2"]
            for pattern in suspicious_patterns:
                if pattern in bytes(packet[TCP].payload).lower():
                    print(f"Suspicious pattern detected from {src_ip}: {pattern}")

           

            packet_data = {
                'src_ip': src_ip,
                'duration': duration,
                'protocol_type': protocol_type,
                'service': service,
                'flag': flags,
                'src_bytes': src_bytes,
                'dst_bytes': dst_bytes,
                'land': land_flag,
                'wrong_fragment': wrong_fragment,
                'urgent': urgent,
                'hot': hot,
                'num_failed_logins': num_failed_logins,
                'logged_in': logged_in,
                'num_compromised': num_compromised,
                'root_shell': root_shell,
                'su_attempted': su_attempted,
                'num_root': num_root,
                'file_creations': file_creations,
                'num_shells': num_shells,
                'num_access_files': num_access_files,
                'num_outbound_cmds': num_outbound_cmds,
                'is_host_login': is_host_login,
                'is_guest_login': is_guest_login,
                'count': packet_count[src_ip],
                'srv_count': srv_count,
                'serror_rate': serror_rate,
                'srv_serror_rate': srv_serror_rate,
                'rerror_rate': rerror_rate,
                'srv_rerror_rate': srv_rerror_rate,
                'same_srv_rate': same_srv_rate,
                'diff_srv_rate': diff_srv_rate,
                'srv_diff_host_rate': dst_host_srv_diff_host_rate,
                'dst_host_count': dst_host_count,
                'dst_host_srv_count': dst_host_srv_count,
                'dst_host_same_srv_rate': dst_host_same_srv_rate,
                'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
                'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
                'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
                'dst_host_serror_rate': serror_rate,
                'dst_host_srv_serror_rate': srv_serror_rate,
                'dst_host_rerror_rate': rerror_rate,
                'dst_host_srv_rerror_rate': srv_rerror_rate
            }
          
            # Append packet data to list
            data.append(packet_data)

# Sniff packets and process them with the process_packet function
filter_expr = "ip and not src net 192.168.1.0/24"

sniff(prn=process_packet, filter=filter_expr, count=100)

# Create DataFrame from collected data
df = pd.DataFrame(data)
#print(df)
original_ips = df.loc[:,'src_ip']

def preprocess_data(df):
    original_ips = df['src_ip'].copy()
    
    def label_encode(df):
        for col in df.columns:
            if col != 'src_ip':  # Skip src_ip
                if isinstance(df[col].iloc[0], dict):  
                    df[col] = df[col].apply(lambda x: list(x.values())[0] if len(x) > 0 else None)   
                
                if df[col].dtype == 'object' or col == 'flag':
                    if col == 'flag':
                        df[col] = df[col].astype(str)
                    label_encoder = LabelEncoder()
                    df[col] = label_encoder.fit_transform(df[col].astype(str))
    
    label_encode(df)
    df.drop(['num_outbound_cmds'], axis=1, inplace=True)  
    
    # Fill NA values for numeric columns only
    numeric_columns = df.select_dtypes(include=[np.number]).columns
    df[numeric_columns] = df[numeric_columns].fillna(df[numeric_columns].mean())
    
    # For non-numeric columns, fill NA with a placeholder value
    non_numeric_columns = df.select_dtypes(exclude=[np.number]).columns
    for col in non_numeric_columns:
        df[col] = df[col].fillna(df[col].mode()[0] if not df[col].mode().empty else 'Unknown')
    
    df['original_ip'] = original_ips
    return df

# Preprocess Scapy data
df_preprocessed = preprocess_data(df)

# Function to select features based on training set features
def select_features(X, feature_importances):
    selected_features = X.columns.tolist()
    selected_features = [f for f in selected_features if f not in ['src_ip', 'original_ip']]
    return X[selected_features[:40]]  # Select up to 40 features, excluding src_ip and original_ip


# Select features from Scapy data
df_selected_features = select_features(df_preprocessed, [])  

# Function to scale features
def scale_features(X):
    features_to_scale = X.columns.difference(['src_ip', 'original_ip'])
    scaler = StandardScaler()
    X_scaled = X.copy()
    X_scaled[features_to_scale] = scaler.fit_transform(X[features_to_scale])
    return X_scaled[features_to_scale]  # Return only the scaled features


# Scale features
df_scaled = scale_features(df_selected_features)

# Load the trained model
def load_model(filename='xgb_model.pkl'):
    return joblib.load(filename)

# Load the model
loaded_model = load_model()

# Predict using loaded model and scaled Scapy data
threshold = 0.1
predictions = loaded_model.predict(df_scaled)
predictions_proba = loaded_model.predict_proba(df_scaled)[:, 1] > threshold
predictions_series = pd.Series(predictions, index=df.index)
results = df.copy()

feature_importances = get_feature_importances(loaded_model, df_preprocessed.columns)


def explain_classification(row, feature_importances, data):
    reasons = []
    for feature, importance in feature_importances:
        try:
            if feature in row.index:
                feature_values = [d.get(feature) for d in data if feature in d]
                if feature_values:
                    numeric_values = [v for v in feature_values if isinstance(v, (int, float))]
                    if numeric_values:
                        avg_value = sum(numeric_values) / len(numeric_values)
                        if isinstance(row[feature], (int, float)) and row[feature] > avg_value:
                            reasons.append(f"{feature}: {row[feature]:.2f} (avg: {avg_value:.2f})")
            if importance > 0.01:
                if isinstance(row[feature], (int, float)):
                    reasons.append(f"{feature}: {row[feature]:.2f} (importance: {importance:.2f})")
                else:
                    reasons.append(f"{feature}: {row[feature]} (importance: {importance:.2f})")
            if len(reasons) >= 5:
                break
        except Exception as e:
            print(f"Error processing feature '{feature}': {e}")
            continue
    return "; ".join(reasons)


results = pd.DataFrame({
    'IP Address': original_ips,
    'Malicious': predictions,
    'Probability': predictions_proba
})


results['Explanation'] = results.apply(
    lambda row: explain_classification(df_selected_features.iloc[row.name], feature_importances, data)
    if row['Malicious'] == 1 else "",
    axis=1
)

def debug_print(message):
    print(f"DEBUG: {message}")

def debug_packet(packet):
       print(f"Packet received: {packet.summary()}")
       return True
# Initialize a set to keep track of already seen malicious IP addresses
seen_malicious_ips = set()

def classify_malicious_ips(df_scaled, loaded_model, original_ips, threshold=0.95):
    # Predict probabilities
    predictions_proba = loaded_model.predict_proba(df_scaled)[:, 1]
    
    # Classify as malicious if probability is above threshold
    predictions = (predictions_proba > threshold).astype(int)
    
    # Create results DataFrame
    results = pd.DataFrame({
        'IP Address': original_ips ,
        'Malicious': predictions,
        'Probability': predictions_proba
    })
    
    # Filter out already seen malicious IPs
    results = results[~results['IP Address'].isin(seen_malicious_ips)]
    
    # Get feature importances
    feature_importances = get_feature_importances(loaded_model, df_scaled.columns)
    
    # Add explanation for malicious IPs
    results['Explanation'] = results.apply(
        lambda row: explain_classification(df_scaled.iloc[row.name], feature_importances, data)
        if row['Malicious'] == 1 else "",
        axis=1
    )
    
    # Convert binary classification to Yes/No
    results['Malicious'] = results['Malicious'].map({1: 'Yes', 0: 'No'})
    
    # Filter to show only malicious results
    malicious_results = results[results['Malicious'] == 'Yes']
    
    # Group by IP Address and keep the entry with the highest probability
    unique_malicious_results = malicious_results.loc[malicious_results.groupby('IP Address')['Probability'].idxmax()]
    unique_malicious_results = unique_malicious_results.sort_values('Probability', ascending=False)
    
    # Remove duplicate IP addresses, keeping only the first occurrence (highest probability)
    unique_malicious_results = unique_malicious_results.drop_duplicates(subset='IP Address', keep='first')
    
    # Update seen malicious IPs
    seen_malicious_ips.update(unique_malicious_results['IP Address'].tolist())
    
    return unique_malicious_results




def main():
    debug_print("Starting packet capture...")
    filter_expr = "ip and not src net 192.168.1.0/24"
    try:
        packets = sniff(prn=process_packet, filter=filter_expr, count=10, timeout=30)
        debug_print(f"Captured {len(packets)} packets")
    except Exception as e:
        debug_print(f"Error during packet capture: {e}")
        return

    if not data:
        debug_print("No packet data collected. Exiting.")
        return

    df = pd.DataFrame(data)
    original_ips = df['src_ip'].copy()  # Store original IPs

    df_preprocessed = preprocess_data(df)
    df_selected_features = select_features(df_preprocessed, [])
    df_scaled = scale_features(df_selected_features)

    loaded_model = load_model()
    malicious_results = classify_malicious_ips(df_scaled, loaded_model, original_ips)
    predictions = loaded_model.predict(df_scaled)
    predictions_proba = loaded_model.predict_proba(df_scaled)[:, 1]
        
    feature_importances = get_feature_importances(loaded_model, df_scaled.columns)

    results = pd.DataFrame({
        'IP Address': original_ips,  # Use the stored original IPs
        'Malicious': predictions,
        'Probability': predictions_proba
    })

    results['Explanation'] = results.apply(
        lambda row: explain_classification(df_scaled.iloc[row.name], feature_importances, data)
        if row['Malicious'] == 1 else "",
        axis=1
    )

    results['Malicious'] = results['Malicious'].map({1: 'Yes', 0: 'No'})
    malicious_results = results[results['Malicious'] == 'Yes']

    # Convert results to JSON
    results_json = malicious_results.to_dict(orient='records')

    # Print JSON output
    print(json.dumps(results_json, indent=4))

if __name__ == "__main__":
    main()