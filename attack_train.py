import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os

# ---------------- Ensure models directory exists ---------------- #
os.makedirs("models", exist_ok=True)

# ---------------- Load dataset ---------------- #
df = pd.read_csv("cybersecurity_attacks.csv")

# ---------------- Detect target column ---------------- #
# Your dataset target column is likely "Attack Type"
possible_labels = ["Attack Type", "attack_type", "Attack", "attack", "Label", "label"]
target_col = None
for col in df.columns:
    if col.strip() in possible_labels:
        target_col = col
        break

if not target_col:
    raise ValueError(f"No valid label column found. Available columns: {list(df.columns)}")

print(f"✅ Using target column: {target_col}")

# ---------------- Select numeric features only ---------------- #
X = df.drop(columns=[target_col])
X = X.select_dtypes(include=["int64", "float64"])  # keep numeric features
y = df[target_col]

if X.shape[1] == 0:
    raise ValueError("❌ No numeric features found! Ensure your dataset has numeric columns for training.")

print(f"✅ Features selected: {list(X.columns)}")
print(f"✅ Total samples: {len(X)}")

# ---------------- Scale features ---------------- #
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---------------- Train-test split ---------------- #
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# ---------------- Train model ---------------- #
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# ---------------- Save model, scaler, features ---------------- #
with open("models/attack_model.pkl", "wb") as f:
    pickle.dump(clf, f)
with open("models/attack_scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("models/attack_features.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)

# ---------------- Save label map for multi-class attacks ---------------- #
label_map = {i: label for i, label in enumerate(y.unique())}
with open("models/attack_label_map.pkl", "wb") as f:
    pickle.dump(label_map, f)

print("✅ Attack model, scaler, features, and label map saved successfully!")