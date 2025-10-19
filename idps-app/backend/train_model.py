import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# Incarcam datele
df = pd.read_csv('db/alerts_for_labeling.csv')
print("Dimensiune DataFrame:", df.shape)
print("Coloane:", df.columns.tolist())
print("Exemplu date:\n", df.head())

# Eliminam randurile fara label
df = df.dropna(subset=['label'])

# Introduce variatie in date prin perturbare etichete (decomentat pentru training real)
label_corruptie = df.sample(frac=0.1)
df.loc[label_corruptie.index, 'label'] = np.random.choice(df['label'].unique(), size=len(label_corruptie))

# Codificare etichete
label_encoder = LabelEncoder()
df['label_encoded'] = label_encoder.fit_transform(df['label'])

# Codificare consistente a feature-urilor
proto_encoder = LabelEncoder()
sig_encoder = LabelEncoder()

df['proto_encoded'] = proto_encoder.fit_transform(df['proto'])
df['signature_encoded'] = sig_encoder.fit_transform(df['signature'])

X = df[['proto_encoded', 'signature_encoded']].copy()
y = df['label_encoded']

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predictii
y_pred = model.predict(X_test)

# Clasificare
print(classification_report(y_test, y_pred))

# Matrice de confuzie
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_, cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')

# Salvare cu timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
os.makedirs("model", exist_ok=True)

model_path = f"model/history/classifier_model_{timestamp}.joblib"
encoder_path = f"model/history/label_encoder_{timestamp}.joblib"
proto_enc_path = f"model/history/proto_encoder_{timestamp}.joblib"
sig_enc_path = f"model/history/sig_encoder_{timestamp}.joblib"
conf_matrix_path = f"model/history/confusion_matrix_{timestamp}.png"

joblib.dump(model, model_path)
joblib.dump(label_encoder, encoder_path)
joblib.dump(proto_encoder, proto_enc_path)
joblib.dump(sig_encoder, sig_enc_path)
plt.savefig(conf_matrix_path)

# Salvare ca si model "curent"
joblib.dump(model, "model/classifier_model.joblib")
joblib.dump(label_encoder, "model/label_encoder.joblib")
joblib.dump(proto_encoder, "model/proto_encoder.joblib")
joblib.dump(sig_encoder, "model/sig_encoder.joblib")
plt.savefig("model/confusion_matrix.png")

print(f"[+] Model salvat in: {model_path}")
print(f"[+] Encoder salvat in: {encoder_path}")
print(f"[+] Confusion Matrix salvata in: {conf_matrix_path}")
print("!!! X shape:", X.shape)
print("Coloane folosite la antrenare:", X.columns.tolist())

importances = model.feature_importances_
feature_names = X.columns.tolist()

with open("model/feature_importance.txt", "w") as f:
    for name, score in zip(feature_names, importances):
        f.write(f"{name}: {score:.4f}\n")
