import os
import json
import firebase_admin
from firebase_admin import credentials, auth

firebase_key_json = os.environ.get("FIREBASE_KEY")

if firebase_key_json:
    firebase_key_dict = json.loads(firebase_key_json)
    cred = credentials.Certificate(firebase_key_dict)
    firebase_admin.initialize_app(cred)
else:
    print("⚠️ Firebase key not found — Firebase not initialized.")
