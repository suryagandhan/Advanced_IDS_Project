import os
import pickle
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from preprocess import prepare_data
import warnings

warnings.filterwarnings('ignore')

# Set random seed for reproducibility
np.random.seed(42)

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout
    from tensorflow.keras.callbacks import EarlyStopping
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("TensorFlow not found. Falling back to Scikit-Learn MLPClassifier for demonstration.")
    from sklearn.neural_network import MLPClassifier

def plot_metrics(history, output_dir="model"):
    """Plot training vs validation accuracy and loss."""
    os.makedirs(output_dir, exist_ok=True)
    
    if TF_AVAILABLE:
        # Plot Accuracy
        plt.figure(figsize=(8, 6))
        plt.plot(history.history['accuracy'], label='Train Accuracy')
        plt.plot(history.history['val_accuracy'], label='Val Accuracy')
        plt.title('Model Accuracy')
        plt.ylabel('Accuracy')
        plt.xlabel('Epoch')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(output_dir, 'accuracy_plot.png'))
        plt.close()
        
        # Plot Loss
        plt.figure(figsize=(8, 6))
        plt.plot(history.history['loss'], label='Train Loss')
        plt.plot(history.history['val_loss'], label='Val Loss')
        plt.title('Model Loss')
        plt.ylabel('Loss')
        plt.xlabel('Epoch')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(output_dir, 'loss_plot.png'))
        plt.close()

def plot_confusion_matrix(y_true, y_pred, labels, output_dir="model"):
    """Plot confusion matrix."""
    os.makedirs(output_dir, exist_ok=True)
    
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    plt.close()

def build_and_train_model():
    dataset_path = "dataset/CICIDS2017_sample.csv"
    model_dir = "model"
    os.makedirs(model_dir, exist_ok=True)
    
    # Preprocess Data
    print("Preparing data...")
    X_train, X_test, y_train, y_test, label_mapping = prepare_data(dataset_path, scaler_path=os.path.join(model_dir, "scaler.pkl"))
    
    # Save label mapping for inference
    with open(os.path.join(model_dir, "label_mapping.pkl"), 'wb') as f:
        pickle.dump(label_mapping, f)
        
    num_classes = len(label_mapping)
    input_dim = X_train.shape[1]
    
    if TF_AVAILABLE:
        print("Building Deep Learning Model with Keras...")
        model = Sequential([
            Dense(64, activation='relu', input_shape=(input_dim,)),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(num_classes, activation='softmax') # Output layer for multi-class
        ])
        
        model.compile(optimizer='adam', 
                      loss='sparse_categorical_crossentropy', 
                      metrics=['accuracy'])
        
        # Callbacks
        early_stop = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
        
        print("Training Model...")
        history = model.fit(
            X_train, y_train,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            callbacks=[early_stop],
            verbose=1
        )
        
        print("Evaluating Model...")
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        
        # Predictions
        y_prob = model.predict(X_test)
        y_pred = np.argmax(y_prob, axis=1)
        
        # Save Model
        model_path = os.path.join(model_dir, 'ids_model.h5')
        model.save(model_path)
        print(f"Model saved to {model_path}")
        
        plot_metrics(history, model_dir)
        
    else:
        print("Building Neural Network with Scikit-Learn MLPClassifier...")
        model = MLPClassifier(hidden_layer_sizes=(64, 32, 16), max_iter=200, random_state=42, early_stopping=True)
        
        print("Training Model...")
        model.fit(X_train, y_train)
        
        print("Evaluating Model...")
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Save Model using pickle since it's sklearn
        model_path = os.path.join(model_dir, 'ids_model.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"Model saved to {model_path}")
        
    # Metrics
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print("\n--- Model Evaluation Results ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    
    # Confusion Matrix
    reverse_mapping = {v: k for k, v in label_mapping.items()}
    labels = [reverse_mapping[i] for i in range(num_classes)]
    plot_confusion_matrix(y_test, y_pred, labels, model_dir)
    print("Visualization plots generated in the 'model/' directory.")

if __name__ == "__main__":
    if not os.path.exists("dataset/CICIDS2017_sample.csv"):
        print("Please generate the dataset first using 'python generate_data.py'")
    else:
        build_and_train_model()
