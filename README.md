# 🚨 Intrusion Detection System (IDS) Using Machine Learning and Streamlit

## 📌 Overview
This project implements a **machine learning-based Intrusion Detection System (IDS)** to detect and classify network traffic as **normal or malicious**. It uses the **CICIDS2017 dataset**, trained using a **Random Forest Classifier**, and is deployed as a user-friendly **Streamlit web app**. Users can register, log in, make predictions using comma-separated values, and view their prediction history—securely stored in **MongoDB**.

---

## 📁 Dataset

- **Name:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Sample Used:** `CICIDS2017_sample.csv` (subset of the full dataset)
- **Features:** 78 numeric features after preprocessing
- **Target Classes:** Includes `BENIGN`, `DoS Hulk`, `PortScan`, `Bot`, etc.

---

## 🧠 Machine Learning Model

- **Notebook:** `N-Model.ipynb`
- **Model Type:** Random Forest Classifier
- **Scaler:** StandardScaler
- **Exported Files:**
  - `best_final_model.pkl` – Trained model
  - `scaler.pkl` – Feature scaler
  - `inference_results.csv` – Sample predictions

---

## 🌐 Web App Features

| Feature                | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| 📝 **User Registration**   | Register new users with hashed password storage                            |
| 🔐 **Login System**        | Authenticated access using session state                                  |
| 📊 **Prediction**          | Input 78 features as comma-separated values to get predictions            |
| 🗃️ **MongoDB Integration** | User data, inputs, and prediction logs are stored securely                 |
| 📜 **View History**        | Users can see all their previous predictions with input and result         |
| 🚪 **Logout**              | Clears session and secures routes                                         |

> 🔑 MongoDB URI should be securely configured before deployment.

---

## 🧰 Prerequisites

- Python 3.7+
- MongoDB Atlas or local MongoDB server
- Required Python libraries (in `requirements.txt`):
  - `streamlit`
  - `pandas`
  - `numpy`
  - `scikit-learn`
  - `joblib`
  - `pymongo`

---

## ⚙️ Installation & Running

```bash
# Clone the repository
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required libraries
pip install -r requirements.txt

# Run the Streamlit app
streamlit run app2.py
```

---

## 🗂️ Project Structure

```plaintext
.
├── CICIDS2017_sample.csv        # Sample data for testing/training
├── N-Model.ipynb                # Jupyter notebook for model training
├── README.md                    # Project documentation
├── app2.py                      # Main Streamlit web application
├── best_final_model.pkl         # Trained Random Forest model
├── inference_results.csv        # Output from predictions
├── requirements.txt             # Python package dependencies
└── scaler.pkl                   # Feature scaling object
```

---

## 🧪 Example Prediction Flow

1. Launch app2.py using Streamlit.
2. Register or login with your credentials.
3. Enter your name and location.
4. Input all 78 features as a comma-separated line.
5. Get prediction result instantly (e.g., BENIGN, DoS Hulk).
6. View your prediction history in the "History" section.

---

## 💾 MongoDB Schema

```plaintext
1. Users Collection

{
  "username": "Alice",
  "email": "alice@example.com",
  "password": "hashed_sha256_password"
}
```

```plaintext
2. Predictions Collection

{
  "email": "alice@example.com",
  "name": "Alice",
  "location": "India",
  "inputs": [0.0, 22.0, ..., 0.02],
  "result": "BENIGN",
  "timestamp": "2025-05-03 16:22:11"
}
```

---

## 🛡️ Security Notes

1. Passwords are hashed using SHA-256.
2. User sessions are managed with st.session_state in Streamlit.
3. Sensitive data like the MongoDB URI should be stored securely, either through environment variables or a configuration file not included in the repository.

---

## 📌 Future Enhancements

1. Support CSV file uploads for batch predictions.
2. Admin panel to monitor users and predictions.
3. Live traffic monitoring and prediction (integration with pcap files).

---

## 👨‍💻 Author

Budhaditya Mukherjee
📧 aditya875320@gmail.com

---
