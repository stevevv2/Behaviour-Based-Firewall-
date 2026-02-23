# anomaly_detection_model_simple.py

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

print("--- Simplified Anomaly Detection Model Trainer (5 Features) ---")

# --- Data Loading ---
print("📥 Loading dataset(s)...")

# Make sure this CSV file is in the same directory as this script
files = ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"] 

dfs = []
for file in files:
    if os.path.exists(file):
        try:
            df = pd.read_csv(file, encoding='latin1', low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f"  ✅ Successfully loaded: {file}")
        except Exception as e:
            print(f"⚠️  Could not load {file}. Error: {e}")
    else:
        print(f"⚠️  File not found: {file}")

if not dfs:
    print("\n❌ No datasets were loaded. Please place CSVs in the same folder. Exiting.")
    exit(1)

df = pd.concat(dfs, ignore_index=True)

# --- Data Cleaning ---
print("\n🧹 Cleaning and preparing data...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
if 'Label' in df.columns:
    df = df[df['Label'] != 'Label'] # Remove duplicate header rows

# --- Feature Engineering & Scaling (5 STABLE FEATURES) ---
# This list contains features that we can reliably calculate in the Ryu controller.
features_list = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Length of Fwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s'
]

# Ensure all required features exist
missing_features = [f for f in features_list if f not in df.columns]
if missing_features:
    print(f"\n❌ Error: Dataset is missing required columns: {missing_features}")
    exit(1)

# Drop any rows that have missing values in our selected features
df.dropna(subset=features_list, inplace=True)

# Convert feature columns to numeric, coercing any errors
X = df[features_list].apply(pd.to_numeric, errors='coerce')
X.dropna(inplace=True) # Drop rows where conversion failed

print("  ✅ Features selected and cleaned.")

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

joblib.dump(scaler, "feature_scaler.pkl")
print("  ✅ 5-Feature scaler saved to feature_scaler.pkl")

# --- Train and Save Isolation Forest Model ---
print("\n🌲 Training Isolation Forest...")
iso_model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42, n_jobs=-1)
iso_model.fit(X_scaled)

joblib.dump(iso_model, "isoforest_model.pkl")
print("  ✅ 5-Feature Isolation Forest saved to isoforest_model.pkl")

print("\n🎉 Model training complete! You are ready to run the Ryu controller.")
