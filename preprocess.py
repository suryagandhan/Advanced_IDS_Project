import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle

def load_data(filepath):
    """Load the dataset from the given filepath."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}")
    df = pd.read_csv(filepath)
    print(f"Dataset loaded with shape: {df.shape}")
    return df

def clean_data(df):
    """Handle missing values and duplicates."""
    # Drop duplicates
    initial_shape = df.shape
    df = df.drop_duplicates()
    
    # Fill or drop NaNs (here we drop)
    df = df.dropna()
    
    print(f"Data cleaned. Rows removed: {initial_shape[0] - df.shape[0]}")
    return df

def preprocess_features(df, scaler_path="model/scaler.pkl", training=True):
    """Normalize numeric features, encode labels, and split."""
    # Separate features and target
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Identify numeric columns for scaling
    numeric_cols = X.select_dtypes(include=[np.number]).columns
    
    scaler = StandardScaler()
    if training:
        X[numeric_cols] = scaler.fit_transform(X[numeric_cols])
        # Save scaler
        os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
        with open(scaler_path, 'wb') as f:
            pickle.dump(scaler, f)
        print(f"Scaler attached and saved to {scaler_path}")
    else:
        # Load scaler
        if os.path.exists(scaler_path):
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            X[numeric_cols] = scaler.transform(X[numeric_cols])
        else:
            raise FileNotFoundError(f"Scaler not found at {scaler_path}")
            
    # Encode labels
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    
    # Print encoding mapping
    mapping = dict(zip(encoder.classes_, encoder.transform(encoder.classes_)))
    print("Label mapping:", mapping)
    
    return X, y_encoded, mapping

def prepare_data(filepath, scaler_path="model/scaler.pkl"):
    """Full pipeline: load, clean, preprocess, and split."""
    df = load_data(filepath)
    df = clean_data(df)
    
    X, y, mapping = preprocess_features(df, scaler_path, training=True)
    
    # Train-test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Testing set: {X_test.shape[0]} samples")
    
    return X_train, X_test, y_train, y_test, mapping

if __name__ == "__main__":
    # Test the preprocessing script
    dataset_path = "dataset/CICIDS2017_sample.csv"
    try:
        X_train, X_test, y_train, y_test, _ = prepare_data(dataset_path)
    except FileNotFoundError as e:
        print(e)
