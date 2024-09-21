import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC, LinearSVC
from sklearn.naive_bayes import BernoulliNB
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Conv1D, Flatten, Input
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils import to_categorical
from scikeras.wrappers import KerasClassifier
from tabulate import tabulate
import warnings
import time

# Ignore warnings
warnings.filterwarnings('ignore')

# Load data
def load_data(file_path):
    return pd.read_csv(file_path)

# Preprocess data
def preprocess_data(df):
    def label_encode(df):
        for col in df.columns:
            if df[col].dtype == 'object':
                label_encoder = LabelEncoder()
                df[col] = label_encoder.fit_transform(df[col])
                
    label_encode(df)
    df.drop(['num_outbound_cmds'], axis=1, inplace=True)
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

# Create Keras models
def create_cnn_model(input_shape, n_classes):
    model = Sequential([
        Input(shape=input_shape),
        Conv1D(filters=64, kernel_size=2, activation='relu'),
        Flatten(),
        Dense(50, activation='relu'),
        Dense(n_classes, activation='softmax')
    ])
    model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def create_lstm_model(input_shape, n_classes):
    model = Sequential([
        Input(shape=input_shape),
        LSTM(50, activation='relu'),
        Dense(n_classes, activation='softmax')
    ])
    model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])
    return model

# Train and evaluate models using cross-validation
def evaluate_models(models, X, y, X_reshaped, y_categorical):
    results = []
    for model in models:
        model_name = model.__class__.__name__
        
        
        start_time = time.time()
        
        # Perform cross-validation
        if model_name == "KerasClassifier":
            scores = cross_val_score(model, X_reshaped, y_categorical, cv=5, scoring='accuracy')
        else:
            scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
        
        # Calculate training time
        training_time = time.time() - start_time
         
        if model_name == "KerasClassifier":
            start_time = time.time()
            model.fit(X_reshaped, y_categorical)  
            model.predict(X_reshaped[:1])   
            prediction_time = time.time() - start_time
        else:
            start_time = time.time()
            model.fit(X, y)   
            model.predict(X[:1])  
            prediction_time = time.time() - start_time
        # Compute mean score
        train_score = np.mean(scores)
        results.append([model_name, train_score, training_time, prediction_time])
    
    return results

 
def main():
    # Load and preprocess data
    data = load_data('Train_data.csv')
    X = data.drop(['class'], axis=1)
    y = data['class']
    X = preprocess_data(X)
    y = LabelEncoder().fit_transform(y)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale the features
    X_train_scaled = scale_features(X_train)
    X_test_scaled = scale_features(X_test)
    
    # Convert y_train to categorical
    y_train_categorical = to_categorical(y_train)
    
    # Define input shape and number of classes
    input_shape = (X_train_scaled.shape[1], 1)
    n_classes = len(np.unique(y_train))
    
    
    models = [
        KNeighborsClassifier(),
        LogisticRegression(max_iter=10000),
        DecisionTreeClassifier(),
        RandomForestClassifier(),
        AdaBoostClassifier(),
        GradientBoostingClassifier(),
        SVC(),
        LinearSVC(max_iter=10000),
        BernoulliNB(),
        LGBMClassifier(),
        XGBClassifier(),
        KerasClassifier(model=create_cnn_model, input_shape=input_shape, n_classes=n_classes, epochs=10, batch_size=32, verbose=0),
        KerasClassifier(model=create_lstm_model, input_shape=input_shape, n_classes=n_classes, epochs=10, batch_size=32, verbose=0)
    ]
    
    # Evaluate models using cross-validation
    results = evaluate_models(models, X_train_scaled, y_train, X_train_scaled.reshape((X_train_scaled.shape[0], X_train_scaled.shape[1], 1)), y_train_categorical)
    
    # Evaluate the best model on the test set
    best_model = RandomForestClassifier()
    best_model.fit(X_train_scaled, y_train)
    test_score = best_model.score(X_test_scaled, y_test)
    print(f"Test set score of the best model: {test_score:.4f}")
    
    # Prepare results for display
    data = pd.DataFrame(results, columns=["Model", "Cross-Validation Score", "Training Time (sec)", "Prediction Time (sec)"])
    plt.figure(figsize=(6, 6))
    sns.barplot(x="Model", y="Cross-Validation Score", data=data)
    plt.xticks(rotation=90)
    plt.title("Cross-Validation Scores")
    plt.show()

    # Print detailed results
    print(tabulate(results, headers=["Model", "Cross-Validation Score", "Training Time (sec)", "Prediction Time (sec)"], tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()