# 🛡️ TrustShield++

**TrustShield++** is an intelligent, Zero Trust–based authentication and access control system. It moves beyond traditional static passwords by combining **dynamic behavioral analysis**, **risk-based authentication**, and **biometric verification (MFA)** to provide adaptive, secure, and seamless access decisions.

---

## ✨ Key Features

- **🧠 Dynamic ML Risk Scoring:** Uses a trained Random Forest model to analyze login contexts (IP address geolocation, device OS, browser type, and time of day) against a user's historical baseline.
- **📸 Biometric Multi-Factor Authentication:** Seamlessly integrates OpenCV-based facial recognition. High-risk logins automatically trigger a webcam challenge to verify the user's physical identity before granting access.
- **🧱 Tri-Level Input Defense Layer:** An early-intercept defense system that evaluates raw inputs for adversarial shifts and malformed payloads. It dynamically categorizes threats into three levels:
  - `ALLOW`: Clean, legitimate inputs pass through smoothly.
  - `MFA`: Suspicious but plausible inputs (e.g., sudden context changes, excessive whitespace) are forced into biometric verification.
  - `BLOCK`: Obvious malicious payloads (e.g., SQL/XSS injections, null bytes, impossible IPs) are instantly rejected.
- **🚨 Continuous Alerting:** Logs all intercepted attacks and suspicious activities locally, with built-in support for real-time Slack webhook notifications.
- **📊 Synthetic Evaluation Harness:** Includes a built-in evaluation harness proving a 100% Attack Detection Rate (ADR) against synthetic manipulated inputs.

## 🛠️ Technology Stack

- **Frontend:** Streamlit (for a fast, interactive Python web UI)
- **Machine Learning:** Scikit-learn, Pandas, NumPy, Joblib
- **Biometrics:** OpenCV (`cv2`)
- **Backend & Utils:** Python, Bcrypt (for secure password hashing), Requests

## 🚀 Getting Started

### Prerequisites
Make sure you have Python 3.9+ installed.

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Arnavjain0805/TrustShield.git
   cd TrustShield
   
2. **Create a Virtual Environment**

  ```bash
  python -m venv .venv

  # On Windows:
  .venv\Scripts\activate
  
  # On Mac/Linux:
  source .venv/bin/activate
  ```

3. **Install Dependencies**

  ```bash
  pip install -r requirements.txt
  Run the Application
  ```

4. **Run the Application**

  ```bash
  streamlit run main.py
  ```

## 🎮 How to Use the Demo

- **Register a User:** Navigate to the "Register" page in the sidebar. Create an account, and if you opt into MFA, the system will briefly capture your face using your webcam to register your biometric baseline.

- **Train the Model:** Go to the "Train Model" page to let the Random Forest model learn the baseline behaviors of your registered users.

- **Login:** Attempt to log in. Try logging in normally, and then try simulating an attack (e.g., typing <script> tags in the device field or attempting a login from a different IP). Watch the Defense Layer and Risk Engine adapt!

## 📈 Evaluation & Performance

TrustShield includes a robust testing suite (evaluation_harness.py). When evaluated against a dataset of clean, suspicious, and malicious synthetic payloads, the defense layer achieves:

- 100% Exact Decision Accuracy

- 0% False Accept Rate (FAR) against malicious payloads

- 0% False Reject Rate (FRR) for legitimate users

(Note: These metrics measure performance against synthetic manipulated inputs in the provided evaluation harness).

### 📄 License

This project is open-source and available under the MIT License.
