import pandas as pd
import numpy as np
from faker import Faker
import random
from datetime import datetime, timedelta
import hashlib

class DataSimulator:
    def __init__(self, num_users=1000):
        self.fake = Faker()
        self.num_users = num_users
        self.persona_types = ['Student', 'Professional', 'Senior', 'Parent', 'Teenager']
        
    def generate_synthetic_data(self):
        """Generate synthetic user data with PII and behavior patterns"""
        users = []
        
        for i in range(self.num_users):
            # Real PII (to be protected)
            real_email = self.fake.email()
            real_name = self.fake.name()
            real_phone = self.fake.phone_number()
            real_address = self.fake.address()
            ssn = self.fake.ssn() if random.random() > 0.7 else None
            
            # User behavior features (non-PII)
            age = random.randint(18, 70)
            avg_session_duration = random.randint(5, 180)  # minutes
            weekly_logins = random.randint(1, 50)
            purchase_frequency = random.random() * 10  # times per month
            preferred_device = random.choice(['Mobile', 'Desktop', 'Tablet'])
            time_of_day_active = random.choice(['Morning', 'Afternoon', 'Evening', 'Night'])
            
            # Determine persona based on behavior (ground truth for training)
            if age < 25 and weekly_logins > 20:
                persona = 'Student'
            elif 25 <= age <= 60 and purchase_frequency > 3:
                persona = 'Professional'
            elif age > 60 and avg_session_duration > 60:
                persona = 'Senior'
            elif preferred_device == 'Mobile' and weekly_logins > 30:
                persona = 'Teenager'
            else:
                persona = 'Parent'
            
            users.append({
                'user_id': i,
                'real_email': real_email,
                'real_name': real_name,
                'real_phone': real_phone,
                'real_address': real_address,
                'ssn': ssn,
                'age': age,
                'avg_session_duration': avg_session_duration,
                'weekly_logins': weekly_logins,
                'purchase_frequency': purchase_frequency,
                'preferred_device': preferred_device,
                'time_of_day_active': time_of_day_active,
                'true_persona': persona
            })
        
        return pd.DataFrame(users)
    
    def generate_anonymized_data(self, df):
        """Create anonymized version for processing"""
        anonymized = df.copy()
        
        # Hash sensitive columns
        anonymized['email_hash'] = anonymized['real_email'].apply(
            lambda x: hashlib.sha256(x.encode()).hexdigest()[:16]
        )
        anonymized['phone_hash'] = anonymized['real_phone'].apply(
            lambda x: hashlib.sha256(x.encode()).hexdigest()[:16]
        )
        
        # Tokenize names (replace with random tokens)
        anonymized['name_token'] = [f"USER_{i:04d}" for i in range(len(anonymized))]
        
        # Remove original PII columns
        columns_to_drop = ['real_email', 'real_name', 'real_phone', 'real_address', 'ssn']
        columns_to_drop = [c for c in columns_to_drop if c in anonymized.columns]
        anonymized = anonymized.drop(columns=columns_to_drop)
        
        return anonymized

if __name__ == "__main__":
    simulator = DataSimulator(100)
    raw_data = simulator.generate_synthetic_data()
    anonymized_data = simulator.generate_anonymized_data(raw_data)
    
    print("Raw Data Sample:")
    print(raw_data[['user_id', 'real_email', 'age', 'true_persona']].head())
    print("\nAnonymized Data Sample:")
    print(anonymized_data[['user_id', 'email_hash', 'age', 'true_persona']].head())
    
    # Save datasets
    raw_data.to_csv('data/raw_users.csv', index=False)
    anonymized_data.to_csv('data/anonymized_users.csv', index=False)