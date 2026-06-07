import os
import pickle
import numpy as np
import pandas as pd
from heuristic_engine import HeuristicDetector

def load_inference_artifacts(model_dir="model"):
    """Load model, scaler, and label mapping."""
    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    mapping_path = os.path.join(model_dir, 'label_mapping.pkl')
    
    # Try loading h5 first, else pkl
    model_h5_path = os.path.join(model_dir, 'ids_model.h5')
    model_pkl_path = os.path.join(model_dir, 'ids_model.pkl')
    
    model = None
    if os.path.exists(model_h5_path):
        from tensorflow.keras.models import load_model
        model = load_model(model_h5_path)
        model_type = 'keras'
    elif os.path.exists(model_pkl_path):
        with open(model_pkl_path, 'rb') as f:
            model = pickle.load(f)
        model_type = 'sklearn'
    else:
        raise FileNotFoundError("No trained model found. Please run train_model.py first.")
        
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
        
    with open(mapping_path, 'rb') as f:
        label_mapping = pickle.load(f)
        
    return model, model_type, scaler, label_mapping

def predict_traffic(features_input, model_dir="model"):
    """
    Predicts if the given network flow features represent an attack or normal traffic.
    features_input: dictionary containing features, or pandas DataFrame for batch
    """
    model, model_type, scaler, label_mapping = load_inference_artifacts(model_dir)
    reverse_mapping = {v: k for k, v in label_mapping.items()}
    
    # Expected order of features
    feature_order = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Flow Bytes/s', 'Packet Length Mean', 'Protocol',
        'Source Port', 'Destination Port'
    ]
    
    is_single = False
    if isinstance(features_input, dict):
        # If dict comes from web form, it might not have the heuristic columns.
        # It's fine, the HeuristicDetector gracefully ignores flows missing 'SYN_Count'.
        cols = list(features_input.keys())
        df = pd.DataFrame([features_input], columns=cols)
        is_single = True
    elif isinstance(features_input, pd.DataFrame):
        df = features_input.copy()
        is_single = False
    else:
        raise ValueError("features_input must be a dict or a pandas DataFrame")
        
    heuristic_results = HeuristicDetector.evaluate(df)
    
    # Ensure only the trained columns are used for ML scaling
    df_ml = df.copy()
    for col in feature_order:
        if col not in df_ml.columns:
            df_ml[col] = 0 # Default if missing
    df_ml = df_ml[feature_order]
    
    # Scale features
    df_scaled = scaler.transform(df_ml)
    
    if model_type == 'keras':
        probs = model.predict(df_scaled, verbose=0)
        pred_class_idx = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1) * 100
    else:
        # Sklearn MLP
        probs = model.predict_proba(df_scaled)
        pred_class_idx = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1) * 100
        
    results = []
    for i in range(len(pred_class_idx)):
        # If heuristic engine caught it, prioritize it 100%
        if heuristic_results[i] is not None:
            results.append(heuristic_results[i])
        else:
            predicted_label = reverse_mapping[pred_class_idx[i]]
            results.append({
                'prediction': predicted_label,
                'confidence': round(confidences[i], 2),
                'is_attack': predicted_label != 'BENIGN'
            })
    
    if is_single:
        return results[0]
    return results

if __name__ == "__main__":
    # Test prediction
    sample_normal = {
        'Flow Duration': 4304672,
        'Total Fwd Packets': 51,
        'Total Backward Packets': 49,
        'Flow Bytes/s': 81984,
        'Packet Length Mean': 816,
        'Protocol': 6,
        'Source Port': 27915,
        'Destination Port': 22
    }
    
    sample_botnet = {
        'Flow Duration': 8500000,
        'Total Fwd Packets': 15,
        'Total Backward Packets': 10,
        'Flow Bytes/s': 500,
        'Packet Length Mean': 120.0,
        'Protocol': 6,
        'Source Port': 12345,
        'Destination Port': 8080
    }
    
    print("Normal Traffic Prediction:")
    print(predict_traffic(sample_normal))
    
    print("\nBotnet Traffic Prediction:")
    print(predict_traffic(sample_botnet))

    print("\nBatch Traffic Prediction:")
    df_test = pd.DataFrame([sample_normal, sample_botnet])
    print(predict_traffic(df_test))
