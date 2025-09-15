import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os

# Ensure directory exists
os.makedirs("trojan_models", exist_ok=True)

# Load dataset
df = pd.read_csv("Trojan_Detection.csv")

# Detect target column
possible_labels = ["label", "trojan", "class", "target", "Category"]
target_col = None
for col in df.columns:
    if col.strip().lower() in [p.lower() for p in possible_labels]:
        target_col = col
        break

if not target_col:
    raise ValueError(f"No valid label column found. Available columns: {list(df.columns)}")

print(f"Using target column: {target_col}")

# Select numeric features only
X = df.drop(columns=[target_col])
X = X.select_dtypes(include=["int64", "float64"])
y = df[target_col]

print(f"Features selected: {list(X.columns)}")
print(f"Total samples: {len(X)}")

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save model, scaler, and features
with open("trojan_models/trojan_model.pkl", "wb") as f:
    pickle.dump(clf, f)
with open("trojan_models/trojan_scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("trojan_models/trojan_features.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)

print("Trojan model, scaler, and feature list saved successfully!")