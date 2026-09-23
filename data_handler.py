import os
import pandas as pd
from config import USERS_CSV, LOGINS_CSV

def ensure_csvs_exist():
    if not os.path.exists(USERS_CSV):
        pd.DataFrame(columns=[
            "UID","Username","Password","Video Path","Registration Timestamp",
            "MFA Enabled","IP","Device","Browser"
        ]).to_csv(USERS_CSV, index=False)

    if not os.path.exists(LOGINS_CSV):
        pd.DataFrame(columns=[
            "Username", "IP", "Device", "Browser",
            "Timestamp", "MFA Enabled", "Outcome",
            "Risk Score", "Risk Decision", "Reasons"
        ]).to_csv(LOGINS_CSV, index=False)

def load_users():
    return pd.read_csv(USERS_CSV)

def save_users(df):
    df.to_csv(USERS_CSV, index=False)

def load_logins():
    if not os.path.exists(LOGINS_CSV):
        return pd.DataFrame(columns=[
            "Username","IP","Device","Browser","Timestamp","MFA Enabled","Outcome", "Risk Score", "Risk Decision", "Reasons"
        ])
    return pd.read_csv(LOGINS_CSV)

def save_logins(df):
    df.to_csv(LOGINS_CSV, index=False)