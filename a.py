#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import joblib  # For saving the model
# Load data
data = pd.read_csv('Train_data.csv')

# Create target variable: 1 for 'attack', 0 for 'normal'
y = data.iloc[:, -1].apply(lambda x: 1 if x == 'attack' else 0)
X = data.iloc[:, :-1]  # Features

# Check the shape of X
print("Number of features in training data:", X.shape[1])
print("Feature names:", X.columns.tolist())
# Identify categorical columns
categorical_columns = X.select_dtypes(include=['object']).columns

# Build a preprocessing pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('cat', OneHotEncoder(handle_unknown="ignore"), categorical_columns),
        ('num', StandardScaler(), X.select_dtypes(exclude=['object']).columns)
    ]
)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Preprocess the data
X_train = preprocessor.fit_transform(X_train)
X_test = preprocessor.transform(X_test)

# Train the Random Forest Classifier
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))

# Save the trained model
joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(preprocessor, 'preprocessor.pkl')

# Input prediction
input_data = input("Enter the data in CSV format (e.g., 0,tcp,ftp_data,...): ")

# Split the input into a list
input_list = input_data.split(",")

# Ensure the correct number of features
expected_feature_count = X.shape[1]
if len(input_list) != expected_feature_count:
    print(f"Error: Expected {expected_feature_count} features but got {len(input_list)}.")
else:
    try:
        numeric_data = []
        categorical_data = []

        for value in input_list:
            if value.replace('.', '', 1).isdigit():  # Check if it's numeric
                numeric_data.append(float(value))
            else:
                categorical_data.append(value)

        # Check if we have the correct number of numeric and categorical features
        if len(numeric_data) + len(categorical_data) != expected_feature_count:
            print("Error: The number of numeric and categorical features does not match the expected count.")
        else:
            # Encode categorical data
            encoded_categorical = preprocessor.transform([categorical_data])  # Transform categorical data

            # Combine numeric and encoded categorical data
            input_data_combined = np.concatenate([numeric_data, encoded_categorical.flatten()])

            # Reshape the input data to match the model's expected input shape
            input_data_reshaped = input_data_combined.reshape(1, -1)  # 1 sample, multiple features

            # Make the prediction
            prediction = model.predict(input_data_reshaped)

            # Print the prediction result
            print("Prediction:", "attack" if prediction[0] == 1 else "normal")  # Converts prediction back to original label

    except ValueError as ve:
        print(f"Value error: {ve}")
    except Exception as e:
        print(f"Error processing input data: {e}")