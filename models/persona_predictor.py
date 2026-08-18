import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import json

class PersonaPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        
    def prepare_features(self, df):
        """Prepare features for training/prediction"""
        # Select behavior features
        behavior_features = [
            'age', 'avg_session_duration', 'weekly_logins', 
            'purchase_frequency'
        ]
        
        # Convert categorical to one-hot
        categorical_features = ['preferred_device', 'time_of_day_active']
        
        # Create feature dataframe
        features = df[behavior_features].copy()
        
        for cat_feat in categorical_features:
            if cat_feat in df.columns:
                dummies = pd.get_dummies(df[cat_feat], prefix=cat_feat)
                features = pd.concat([features, dummies], axis=1)
        
        self.feature_columns = features.columns.tolist()
        return features
    
    def train(self, df):
        """Train the persona prediction model"""
        # Prepare features and labels
        X = self.prepare_features(df)
        y = self.label_encoder.fit_transform(df['true_persona'])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
# Remove 'stratify=y' parameter
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model Accuracy: {accuracy:.2f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                    target_names=self.label_encoder.classes_))
        
        return accuracy
    
    def predict(self, df):
        """Predict personas for new data"""
        X = self.prepare_features(df)
        X_scaled = self.scaler.transform(X)
        
        # Get predictions
        encoded_preds = self.model.predict(X_scaled)
        persona_preds = self.label_encoder.inverse_transform(encoded_preds)
        
        # Get prediction probabilities
        probabilities = self.model.predict_proba(X_scaled)
        
        return persona_preds, probabilities
    
    def add_differential_privacy(self, epsilon=1.0):
        """Add basic differential privacy by adding noise to features"""
        # This is a simplified version - in practice, use libraries like TensorFlow Privacy
        print(f"Adding differential privacy with epsilon={epsilon}")
        
        # We'll implement DP-SGD or noise addition in a more advanced version
        return self
    
    def save_model(self, path='models/'):
        """Save model and preprocessors"""
        joblib.dump(self.model, f'{path}/persona_model.pkl')
        joblib.dump(self.scaler, f'{path}/scaler.pkl')
        joblib.dump(self.label_encoder, f'{path}/label_encoder.pkl')
        
        # Save feature columns
        with open(f'{path}/feature_columns.json', 'w') as f:
            json.dump(self.feature_columns, f)
    
    def load_model(self, path='models/'):
        """Load saved model"""
        self.model = joblib.load(f'{path}/persona_model.pkl')
        self.scaler = joblib.load(f'{path}/scaler.pkl')
        self.label_encoder = joblib.load(f'{path}/label_encoder.pkl')
        
        with open(f'{path}/feature_columns.json', 'r') as f:
            self.feature_columns = json.load(f)

if __name__ == "__main__":
    # Test the model
    data = pd.read_csv('data/anonymized_users.csv')
    predictor = PersonaPredictor()
    accuracy = predictor.train(data)
    predictor.save_model()