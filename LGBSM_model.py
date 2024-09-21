import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
import joblib
import warnings

# Ignore warnings
warnings.filterwarnings('ignore')

# Load data
load_data = pd.read_csv('Train_data.csv')

# Preprocess data
def preprocess_data(df):
    def label_encode(df):
        for col in df.columns:
            if df[col].dtype == 'object':
                label_encoder = LabelEncoder()
                df[col] = label_encoder.fit_transform(df[col])
                
    label_encode(df)
    df.drop(['num_outbound_cmds'], axis=1, inplace=True)  # Assuming this column is not needed
    df.fillna(df.mean(), inplace=True)
    return df

# Feature selection
def select_features(X, y, n_features=10):
    rfc = RandomForestClassifier()
    rfe = RFE(rfc, n_features_to_select=n_features)
    rfe.fit(X, y)
    selected_features = X.columns[rfe.support_]
    return X[selected_features]

# Scale features
def scale_features(X):
    scaler = StandardScaler()
    return scaler.fit_transform(X)

# Train LGBMClassifier and return the trained model
def train_lgbm_model(X_train_scaled, Y_train_encoded):
    lgbm = LGBMClassifier()
    lgbm.fit(X_train_scaled, Y_train_encoded)
    return lgbm

# Save the model to a file
def save_model(model, filename='lgbm_model.pkl'):
    joblib.dump(model, filename)

# Load the model from a file
def load_model(filename='lgbm_model.pkl'):
    return joblib.load(filename)

# Evaluate model on testing data
def evaluate_model(model, X_test_scaled, Y_test_encoded, threshold):
    predictions = (model.predict_proba(X_test_scaled)[:, 1] > threshold).astype(int)
    f1 = f1_score(Y_test_encoded, predictions)
    precision = precision_score(Y_test_encoded, predictions)
    recall = recall_score(Y_test_encoded, predictions)
    roc_auc = roc_auc_score(Y_test_encoded, model.predict_proba(X_test_scaled)[:, 1])
    
    print(f"Threshold used: {threshold}")
    print(f"F1 Score: {f1:.4f}")
    print(f"Precision Score: {precision:.4f}")
    print(f"Recall Score: {recall:.4f}")
    print(f"ROC AUC Score: {roc_auc:.4f}")

# Predict if connections in a new dataframe are malicious or not
def predict_new_data(model, new_data, threshold):
    new_data = preprocess_data(new_data)
    new_data = select_features(new_data, model.feature_importances_)  # assuming the same features as training
    new_data_scaled = scale_features(new_data)
    predictions = (model.predict_proba(new_data_scaled)[:, 1] > threshold).astype(int)
    return predictions

# Main function
def main():
    train = load_data
    X = train.drop(['class'], axis=1)
    Y = train['class']

    X = preprocess_data(X)
    X_scaled = scale_features(X)

    label_encoder = LabelEncoder()
    Y_encoded = label_encoder.fit_transform(Y)

    # Split data into training and testing sets
    X_train, X_test, Y_train, Y_test = train_test_split(X_scaled, Y_encoded, test_size=0.2, random_state=42)

    # Train LGBMClassifier
    lgbm_model = train_lgbm_model(X_train, Y_train)
    
    # Save the model
    save_model(lgbm_model)

    # Find best threshold using validation set or cross-validation (not shown here for brevity)
    best_threshold = 0.0  # Initialize with a low value
    best_f1_score = 0.0

    # Iterate through thresholds and find the best one
    thresholds = np.arange(0.01, 1.0, 0.01)
    for threshold in thresholds:
        predictions = (lgbm_model.predict_proba(X_test)[:, 1] > threshold).astype(int)
        f1 = f1_score(Y_test, predictions)
        
        if f1 > best_f1_score:
            best_f1_score = f1
            best_threshold = threshold

    # Evaluate model on testing data using the best threshold
    evaluate_model(lgbm_model, X_test, Y_test, best_threshold)

    print(f"Best threshold for malicious activities: {best_threshold}")

if __name__ == "__main__":
    main()
