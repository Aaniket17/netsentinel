import os
import glob
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# 1. Load all .parquet dataset files from data/raw/
raw_files = glob.glob(os.path.join("data", "raw", "*.parquet"))
print(f"Found {len(raw_files)} dataset files.")

dfs = []
for f in raw_files:
    temp_df = pd.read_parquet(f)
    temp_df.columns = temp_df.columns.str.strip()
    if len(temp_df) > 50000:
        temp_df = temp_df.sample(n=50000, random_state=42)
    dfs.append(temp_df)

df = pd.concat(dfs, ignore_index=True)

# 2. Clean Infinity and NaN values
df = df.replace([np.inf, -np.inf], np.nan).dropna()

# 3. Standardize multi-class attack labels
def clean_label(val):
    s = str(val).strip()
    upper_s = s.upper()
    if upper_s == "BENIGN":
        return "Benign"
    elif "DDOS" in upper_s:
        return "DDoS"
    elif "DOS" in upper_s:
        return "DoS"
    elif "PORTSCAN" in upper_s:
        return "Portscan"
    elif "BOT" in upper_s:
        return "Botnet"
    elif "PATATOR" in upper_s or "BRUTE" in upper_s:
        return "Bruteforce"
    elif "WEB ATTACK" in upper_s or "XSS" in upper_s or "SQL" in upper_s:
        return "WebAttacks"
    elif "INFILTRATION" in upper_s:
        return "Infiltration"
    return s

df["Label"] = df["Label"].apply(clean_label)

# 4. Retain only numeric features
X = df.drop(columns=["Label"]).select_dtypes(include=[np.number])
y = df["Label"]

print("\nAttack categories found:\n", y.value_counts())

# 5. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 6. Train multi-class Random Forest model
print("\nTraining multi-class Random Forest model...")
model = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 7. Evaluate model
y_pred = model.predict(X_test)
print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 8. Save updated multi-class model
os.makedirs("models", exist_ok=True)
joblib.dump(model, os.path.join("models", "baseline_rf.joblib"))

# 9. Save processed baseline schema
os.makedirs(os.path.join("data", "processed"), exist_ok=True)
cleaned_df = X.copy()
cleaned_df["Label"] = y
cleaned_df.to_parquet(os.path.join("data", "processed", "cleaned_ddos_flows.parquet"), index=False)

print("\nSuccess! Multi-class model saved to 'models/baseline_rf.joblib'.")