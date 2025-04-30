import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import http.client
import json
from typing import Optional, Dict, List, Tuple
import time
import os
import pyrebase
import requests
from dotenv import load_dotenv

# Define theme color schemes
THEMES = {
    'satyr_stock': {
        'name': 'SATyr Stock Theme',
        'splash_screen': '#D8AA2A',  # Warm gold
        'app_background': '#1A1A2E',  # Dark navy
        'sidebar_background': '#2A2A4E',  # Slightly brighter navy
        'input_background': '#B2984A',  # Dark shade of gold
        'text_color': '#FFFFFF',
        'visit_counter_background': '#D8AA2A80',  # Translucent gold
        'visit_counter_text': '#FFFFFF',
        'floating_message_background': '#B2984A',  # Dark shade of gold
        'button_form_default': '#68E636',  # Green
        'button_form_hover': '#50B62B',
        'button_form_active': '#388E1F',
        'button_sidebar_default': '#007AFF',  # Blue
        'button_sidebar_hover': '#0066CC',
        'button_sidebar_active': '#0055B3',
        'button_history_default': '#2A2A4E',  # Match sidebar
        'button_history_hover': '#3A3A5E',
        'button_history_active': '#1A1A3E',
        'user_message': '#007AFF',  # Blue
        'ai_message': '#68E636'  # Green
    },
    'floral': {
        'name': 'Floral Theme',
        'splash_screen': '#FFB7C5',  # Cherry blossom pink
        'app_background': '#FCE4EC',  # Light pink
        'sidebar_background': '#F8BBD0',  # Soft pink
        'input_background': '#D81B60',  # Deep pink
        'text_color': '#4A2E2A',  # Dark brown for contrast
        'visit_counter_background': '#FFCDD280',  # Translucent pink
        'visit_counter_text': '#4A2E2A',
        'floating_message_background': '#D81B60',  # Deep pink
        'button_form_default': '#F06292',  # Rose pink
        'button_form_hover': '#EC407A',
        'button_form_active': '#D81B60',
        'button_sidebar_default': '#AB47BC',  # Lavender
        'button_sidebar_hover': '#9C27B0',
        'button_sidebar_active': '#8E24AA',
        'button_history_default': '#F8BBD0',  # Soft pink
        'button_history_hover': '#F48FB1',
        'button_history_active': '#F06292',
        'user_message': '#AB47BC',  # Lavender
        'ai_message': '#F06292'  # Rose pink
    },
    'aqua': {
        'name': 'Aqua Theme',
        'splash_screen': '#4FC3F7',  # Sky blue
        'app_background': '#E0F7FA',  # Light cyan
        'sidebar_background': '#B2EBF2',  # Soft cyan
        'input_background': '#0288D1',  # Deep blue
        'text_color': '#01579B',  # Dark blue
        'visit_counter_background': '#4FC3F780',  # Translucent sky blue
        'visit_counter_text': '#01579B',
        'floating_message_background': '#0288D1',  # Deep blue
        'button_form_default': '#29B6F6',  # Light blue
        'button_form_hover': '#039BE5',
        'button_form_active': '#0288D1',
        'button_sidebar_default': '#26A69A',  # Teal
        'button_sidebar_hover': '#009688',
        'button_sidebar_active': '#00897B',
        'button_history_default': '#B2EBF2',  # Soft cyan
        'button_history_hover': '#80DEEA',
        'button_history_active': '#4FC3F7',
        'user_message': '#26A69A',  # Teal
        'ai_message': '#29B6F6'  # Light blue
    },
    'golden': {
        'name': 'Golden Theme',
        'splash_screen': '#FFD700',  # Gold
        'app_background': '#FFF8E1',  # Light gold
        'sidebar_background': '#FFECB3',  # Soft gold
        'input_background': '#D4A017',  # Deep gold
        'text_color': '#3E2723',  # Dark brown
        'visit_counter_background': '#FFD70080',  # Translucent gold
        'visit_counter_text': '#3E2723',
        'floating_message_background': '#D4A017',  # Deep gold
        'button_form_default': '#FFCA28',  # Amber
        'button_form_hover': '#FFB300',
        'button_form_active': '#FFA000',
        'button_sidebar_default': '#FBC02D',  # Yellow gold
        'button_sidebar_hover': '#F9A825',
        'button_sidebar_active': '#F57F17',
        'button_history_default': '#FFECB3',  # Soft gold
        'button_history_hover': '#FFE082',
        'button_history_active': '#FFCA28',
        'user_message': '#FBC02D',  # Yellow gold
        'ai_message': '#FFCA28'  # Amber
    }
}

# State management
class AppState:
    def __init__(self):
        self.splash_shown = False
        self.show_settings = False
        self.theme = 'satyr_stock'
        self.logged_in = False
        self.chatbot = None
        self.chat_history = []
        self.user_name = None
        self.selected_conversation_index = None
        self.show_double_click_message = False
        self.user_email = None
        self.user_token = None
        self.refresh_token = None
        self.visit_count = 0
        self.signup_clicked = False
        self.signup_email = ""
        self.signup_password = ""
        self.pending_verification = False
        self.temp_user_id = None
        self.temp_username = None

state = AppState()

# Load environment variables
load_dotenv()

# Firebase configuration
firebase_config = {
    "apiKey": os.getenv("API_KEY", ""),
    "authDomain": os.getenv("AUTH_DOMAIN", ""),
    "projectId": os.getenv("PROJECT_ID", ""),
    "storageBucket": os.getenv("STORAGE_BUCKET", ""),
    "messagingSenderId": os.getenv("MESSAGING_SENDER_ID", ""),
    "appId": os.getenv("APP_ID", ""),
    "measurementId": os.getenv("MEASUREMENT_ID", ""),
    "databaseURL": os.getenv("DATABASE_URL", "")
}

# Initialize Firebase
try:
    firebase = pyrebase.initialize_app(firebase_config)
    auth = firebase.auth()
    db = firebase.database()
except Exception as e:
    print(f"Failed to initialize Firebase: {str(e)}")
    exit()

# Function to refresh user token
def refresh_user_token(refresh_token: str) -> Optional[str]:
    try:
        response = requests.post(
            'https://securetoken.googleapis.com/v1/token?key=' + os.getenv("API_KEY"),
            data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }
        )
        if response.status_code == 200:
            data = response.json()
            new_id_token = data.get('id_token')
            new_refresh_token = data.get('refresh_token')
            if new_id_token:
                state.user_token = new_id_token
                state.refresh_token = new_refresh_token
                return new_id_token
            else:
                messagebox.showerror("Error", "Failed to obtain new ID token from refresh response.")
                return None
        else:
            messagebox.showerror("Error", f"Failed to refresh token: {response.text}")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Error refreshing token: {str(e)}")
        return None

# AI Client
class SATyrAI:
    def __init__(self):
        self.api_key = "rzZknlckhFldf2YV2AcpHlxmknkcL7Bo"
        self.domain = "km-pfrdhsi"
        self.base_url = "api.personal.ai"
        self.session_id = None
        self.user_name = None
        self.context = None
        self.conn = http.client.HTTPSConnection(self.base_url, timeout=30)

    def __del__(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

    def _create_payload(self, text: str, context: Optional[str] = None) -> Dict:
        payload = {
            "Text": text,
            "DomainName": self.domain,
            "UserName": self.user_name or "Guest"
        }
        if context:
            payload["Context"] = context
        if self.session_id:
            payload["SessionId"] = self.session_id
        return payload

    def _log_api_error(self, status: int, reason: str, response_body: str) -> str:
        error_details = (
            f"API Error: {status} {reason}\n"
            f"Response: {response_body[:1000]}\n"
            f"Domain: {self.domain}\n"
            f"API Key (first 4 chars): {self.api_key[:4]}...\n"
            "Troubleshooting:\n"
            "- Check if API key is valid and not expired.\n"
            "- Verify domain is correct for your Personal AI account.\n"
            "- Ensure network connectivity and no firewall is blocking api.personal.ai.\n"
            "- Check for rate limits (HTTP 429) or server issues (HTTP 500)."
        )
        return error_details

    def send_request(self, text: str, context: Optional[str] = None) -> str:
        if not text or not isinstance(text, str) or not text.strip():
            return "[Error] Invalid or empty input text"

        try:
            payload = json.dumps(self._create_payload(text, context))
            headers = {
                'Content-Type': 'application/json',
                'x-api-key': self.api_key
            }

            self.conn.request("POST", "/v1/message", payload, headers)
            response = self.conn.getresponse()
            response_data = response.read().decode()

            if response.status == 200:
                try:
                    data = json.loads(response_data)
                    self.session_id = data.get("SessionId", self.session_id)
                    self.context = data.get("ai_message", "[Error] No AI message in response")
                    return self.context
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON response: {response_data[:100]}")
                    return f"[Error] Invalid JSON response: {str(e)}"
            else:
                error_details = self._log_api_error(response.status, response.reason, response_data)
                print(error_details)
                return f"[Error] API request failed: {response.status} - {response.reason}"

        except http.client.HTTPException as e:
            print(f"HTTP error occurred: {str(e)}")
            return f"[Error] HTTP error: {str(e)}"
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return f"[Error] Network or API error: {str(e)}"

    def reset(self):
        self.session_id = None
        self.context = None

# Initialize chatbot
if state.chatbot is None:
    state.chatbot = SATyrAI()

# Tkinter Application
class SATyrApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SATyr")
        self.root.geometry("800x600")
        self.current_theme = THEMES[state.theme]
        self.apply_theme()

        # Splash screen
        if not state.splash_shown:
            self.show_splash_screen()
            state.splash_shown = True

        # Initialize UI
        self.frames = {}
        self.setup_login_page()

    def apply_theme(self):
        self.root.configure(bg=self.current_theme['app_background'])

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def show_splash_screen(self):
        splash = tk.Toplevel(self.root)
        splash.geometry("300x200")
        splash.configure(bg=self.current_theme['splash_screen'])
        splash.overrideredirect(True)
        tk.Label(splash, text="SATyr", font=("Arial", 24), bg=self.current_theme['splash_screen'], fg=self.current_theme['text_color']).pack(expand=True)
        self.root.after(1000, splash.destroy)

    def setup_login_page(self):
        if "login" not in self.frames:
            self.frames["login"] = tk.Frame(self.root, bg=self.current_theme['app_background'])
        frame = self.frames["login"]
        self.clear_frame(frame)

        tk.Label(frame, text="🔐 SATyr Login", font=("Arial", 20), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack(pady=10)
        tk.Label(frame, text="Welcome to SATyr. Please log in or sign up to continue.", bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()

        tk.Label(frame, text="📧 Email", bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        email_entry = tk.Entry(frame, bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
        email_entry.pack()

        tk.Label(frame, text="🔒 Password", bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        password_entry = tk.Entry(frame, show="*", bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
        password_entry.pack()

        btn_frame = tk.Frame(frame, bg=self.current_theme['app_background'])
        btn_frame.pack(pady=10)

        login_btn = tk.Button(btn_frame, text="🔓 Login", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                              command=lambda: self.handle_login(email_entry.get(), password_entry.get()))
        login_btn.pack(side=tk.LEFT, padx=5)

        signup_btn = tk.Button(btn_frame, text="📝 Sign Up", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                               command=lambda: self.handle_signup_start(email_entry.get(), password_entry.get()))
        signup_btn.pack(side=tk.LEFT, padx=5)

        # Forgot Password
        forgot_frame = tk.LabelFrame(frame, text="Forgot Password?", bg=self.current_theme['app_background'], fg=self.current_theme['text_color'])
        forgot_frame.pack(pady=10, fill="x")

        tk.Label(forgot_frame, text="📧 Enter your email to reset password", bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        reset_email_entry = tk.Entry(forgot_frame, bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
        reset_email_entry.pack()

        tk.Button(forgot_frame, text="🔄 Send Reset Email", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=lambda: self.handle_reset_password(reset_email_entry.get())).pack(pady=5)

        frame.pack(fill="both", expand=True)

    def handle_login(self, email: str, password: str):
        if "@" not in email:
            messagebox.showerror("Error", "Please enter a valid email address containing '@'.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

        try:
            user = auth.sign_in_with_email_and_password(email, password)
            state.logged_in = True
            state.user_email = email
            state.user_token = user['idToken']
            state.refresh_token = user['refreshToken']
            state.user_name = self.fetch_username(email, user['idToken']) or email.split("@")[0]
            state.chat_history = self.load_chat_history(email, user['idToken'])
            self.update_visit_counter()
            messagebox.showinfo("Success", f"Logged in as {state.user_name}")
            self.setup_main_page()
        except Exception as e:
            error_msg = str(e)
            if "INVALID_LOGIN_CREDENTIALS" in error_msg:
                messagebox.showerror("Error", "Incorrect email or password.")
            else:
                messagebox.showerror("Error", f"Authentication failed: {error_msg}")

    def handle_signup_start(self, email: str, password: str):
        if "@" not in email:
            messagebox.showerror("Error", "Please enter a valid email address containing '@'.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

        state.signup_clicked = True
        state.signup_email = email
        state.signup_password = password
        self.setup_signup_page()

    def setup_signup_page(self):
        if "signup" not in self.frames:
            self.frames["signup"] = tk.Frame(self.root, bg=self.current_theme['app_background'])
        frame = self.frames["signup"]
        self.clear_frame(frame)

        tk.Label(frame, text="📝 Sign Up", font=("Arial", 20), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack(pady=10)

        if not state.pending_verification:
            tk.Label(frame, text="Choose a username:", bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
            username_entry = tk.Entry(frame, bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
            username_entry.pack()

            tk.Button(frame, text="Confirm Sign-Up", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                      command=lambda: self.handle_confirm_signup(username_entry.get())).pack(pady=5)
        else:
            tk.Label(frame, text="Please click the verification link in your email and return here to complete sign-up.",
                     bg=self.current_theme['app_background'], fg=self.current_theme['text_color'], wraplength=600).pack(pady=10)
            tk.Button(frame, text="Check Verification", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                      command=self.handle_verify_signup).pack(pady=5)

        tk.Button(frame, text="Cancel Sign-Up", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=self.handle_cancel_signup).pack(pady=5)

        frame.pack(fill="both", expand=True)

    def handle_confirm_signup(self, username: str):
        if not username or not username.strip():
            messagebox.showerror("Error", "Please enter a valid username.")
            return

        try:
            user = auth.create_user_with_email_and_password(state.signup_email, state.signup_password)
            state.temp_user_id = user['localId']
            state.user_token = user['idToken']
            state.refresh_token = user['refreshToken']
            state.temp_username = username
            safe_email = state.signup_email.replace(".", "_").replace("@", "_")
            db.child("pending_users").child(safe_email).set(
                {
                    "username": username,
                    "email": state.signup_email,
                    "password": state.signup_password,
                    "temp_user_id": state.temp_user_id,
                    "created_at": time.time()
                },
                token=state.user_token
            )
            verification_response = requests.post(
                'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=' + os.getenv("API_KEY"),
                json={
                    'requestType': 'VERIFY_EMAIL',
                    'idToken': state.user_token,
                    'email': state.signup_email
                }
            )
            if verification_response.status_code == 200:
                messagebox.showinfo("Info", "Verification email sent! Click the link in your inbox, then return here to complete sign-up.")
                state.pending_verification = True
                self.setup_signup_page()
            else:
                messagebox.showerror("Error", f"Failed to send verification email: {verification_response.text}")
        except Exception as e:
            error_msg = str(e)
            if "EMAIL_EXISTS" in error_msg:
                messagebox.showerror("Error", "This email is already registered. Please log in or use a different email.")
            else:
                messagebox.showerror("Error", f"Failed to initiate sign-up: {str(e)}")

    def handle_verify_signup(self):
        try:
            user = auth.sign_in_with_email_and_password(state.signup_email, state.signup_password)
            state.user_token = user['idToken']
            state.refresh_token = user['refreshToken']
            user_info = requests.post(
                'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + os.getenv("API_KEY"),
                json={'idToken': state.user_token}
            )
            if user_info.status_code == 200:
                user_data = user_info.json()
                if user_data.get('users', [{}])[0].get('emailVerified', False):
                    temp_user_info = user_data.get('users', [{}])[0]
                    temp_local_id = temp_user_info.get('localId')
                    if temp_local_id:
                        delete_response = requests.post(
                            'https://identitytoolkit.googleapis.com/v1/accounts:delete?key=' + os.getenv("API_KEY"),
                            json={'idToken': state.user_token, 'localId': temp_local_id}
                        )
                        if delete_response.status_code != 200:
                            messagebox.showerror("Error", f"Failed to delete temporary user: {delete_response.text}")
                            return
                    final_user = auth.create_user_with_email_and_password(state.signup_email, state.signup_password)
                    state.user_token = final_user['idToken']
                    state.refresh_token = final_user['refreshToken']
                    safe_email = state.signup_email.replace(".", "_").replace("@", "_")
                    db.child("users").child(safe_email).set({"username": state.temp_username}, token=state.user_token)
                    db.child("pending_users").child(safe_email).remove()
                    messagebox.showinfo("Success", "Account creation successful! Enjoy mate :) ")
                    state.logged_in = True
                    state.user_email = state.signup_email
                    state.user_name = state.temp_username
                    state.signup_clicked = False
                    state.signup_email = ""
                    state.signup_password = ""
                    state.pending_verification = False
                    state.temp_user_id = None
                    state.temp_username = None
                    self.setup_main_page()
                else:
                    messagebox.showinfo("Info", "Please click the verification link in your email and return here to complete sign-up.")
            else:
                messagebox.showerror("Error", f"Failed to check verification status: {user_info.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Error checking verification: {str(e)}")

    def handle_cancel_signup(self):
        try:
            safe_email = state.signup_email.replace(".", "_").replace("@", "_")
            pending_data = db.child("pending_users").child(safe_email).get().val()
            if pending_data and pending_data.get("temp_user_id"):
                requests.post(
                    'https://identitytoolkit.googleapis.com/v1/accounts:delete?key=' + os.getenv("API_KEY"),
                    json={'idToken': state.user_token, 'localId': pending_data["temp_user_id"]}
                )
            db.child("pending_users").child(safe_email).remove()
            messagebox.showinfo("Info", "Sign-up cancelled. Pending data and temporary user removed.")
            state.signup_clicked = False
            state.signup_email = ""
            state.signup_password = ""
            state.pending_verification = False
            state.temp_user_id = None
            state.temp_username = None
            self.setup_login_page()
        except Exception as e:
            messagebox.showerror("Error", f"Error cancelling sign-up: {str(e)}")

    def handle_reset_password(self, email: str):
        if "@" not in email:
            messagebox.showerror("Error", "Please enter a valid email address containing '@'.")
            return
        try:
            auth.send_password_reset_email(email)
            messagebox.showinfo("Success", "Password reset email sent! Check your inbox.")
        except Exception as e:
            error_msg = str(e)
            if "EMAIL_NOT_FOUND" in error_msg:
                messagebox.showerror("Error", "No account found with this email.")
            else:
                messagebox.showerror("Error", f"Failed to send reset email: {error_msg}")

    def setup_main_page(self):
        if "main" not in self.frames:
            self.frames["main"] = tk.Frame(self.root, bg=self.current_theme['app_background'])
        frame = self.frames["main"]
        self.clear_frame(frame)

        # Sidebar
        sidebar = tk.Frame(frame, bg=self.current_theme['sidebar_background'], width=200)
        sidebar.pack(side=tk.LEFT, fill="y")

        tk.Label(sidebar, text="SATyr", font=("Arial", 20), bg=self.current_theme['sidebar_background'], fg=self.current_theme['text_color']).pack(pady=10)
        tk.Label(sidebar, text=f"Visits: {state.visit_count}", bg=self.current_theme['visit_counter_background'], fg=self.current_theme['visit_counter_text']).pack()

        tk.Label(sidebar, text="Conversations", font=("Arial", 14), bg=self.current_theme['sidebar_background'], fg=self.current_theme['text_color']).pack(pady=5)
        self.conversation_frame = tk.Frame(sidebar, bg=self.current_theme['sidebar_background'])
        self.conversation_frame.pack(fill="both", expand=True)
        self.update_conversation_list()

        tk.Button(sidebar, text="🔄 New Session", bg=self.current_theme['button_sidebar_default'], fg=self.current_theme['text_color'],
                  command=self.handle_new_session).pack(fill="x", pady=5)
        tk.Button(sidebar, text="⚙️ Settings", bg=self.current_theme['button_sidebar_default'], fg=self.current_theme['text_color'],
                  command=self.setup_settings_page).pack(fill="x", pady=5)
        tk.Button(sidebar, text="🚪 Logout", bg=self.current_theme['button_sidebar_default'], fg=self.current_theme['text_color'],
                  command=self.handle_logout).pack(fill="x", pady=5)

        # Main chat area
        chat_frame = tk.Frame(frame, bg=self.current_theme['app_background'])
        chat_frame.pack(side=tk.LEFT, fill="both", expand=True)

        tk.Label(chat_frame, text="SATyr - your SAT saviour", font=("Arial", 20), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack(pady=10)

        self.chat_display = scrolledtext.ScrolledText(chat_frame, bg=self.current_theme['app_background'], fg=self.current_theme['text_color'], height=20, state='disabled')
        self.chat_display.pack(fill="both", expand=True, padx=10)

        input_frame = tk.Frame(chat_frame, bg=self.current_theme['app_background'])
        input_frame.pack(fill="x", pady=10)

        self.input_entry = tk.Entry(input_frame, bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
        self.input_entry.pack(side=tk.LEFT, fill="x", expand=True, padx=5)
        tk.Button(input_frame, text="Send", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=self.handle_send_message).pack(side=tk.LEFT, padx=5)

        frame.pack(fill="both", expand=True)
        self.update_chat_display()

    def update_conversation_list(self):
        for widget in self.conversation_frame.winfo_children():
            widget.destroy()
        if state.chat_history:
            for idx, thread in enumerate(state.chat_history):
                if not isinstance(thread, dict) or "initial" not in thread:
                    continue
                initial = thread.get("initial")
                if not isinstance(initial, (list, tuple)) or len(initial) < 1:
                    continue
                user_msg = initial[0]
                label = f"{user_msg[:20]}{'...' if len(user_msg) > 20 else ''}"
                tk.Button(self.conversation_frame, text=label, bg=self.current_theme['button_history_default'], fg=self.current_theme['text_color'],
                          command=lambda i=idx: self.select_conversation(i)).pack(fill="x")
        else:
            tk.Label(self.conversation_frame, text="No conversations yet.", bg=self.current_theme['sidebar_background'], fg=self.current_theme['text_color']).pack()

    def select_conversation(self, idx: int):
        state.selected_conversation_index = idx
        self.update_chat_display()

    def update_chat_display(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        if state.selected_conversation_index is not None and 0 <= state.selected_conversation_index < len(state.chat_history):
            thread = state.chat_history[state.selected_conversation_index]
            user_msg, ai_msg = thread["initial"]
            self.chat_display.insert(tk.END, f"🧑 {state.user_name}: {user_msg}\n", "user")
            self.chat_display.insert(tk.END, f"🤖 SATyr: {ai_msg}\n", "ai")
            for follow_up_user_msg, follow_up_ai_msg in thread.get("follow_ups", []):
                self.chat_display.insert(tk.END, f"🧑 {state.user_name}: {follow_up_user_msg}\n", "user")
                self.chat_display.insert(tk.END, f"🤖 SATyr: {follow_up_ai_msg}\n", "ai")
        self.chat_display.config(state='disabled')
        self.chat_display.tag_config("user", foreground=self.current_theme['user_message'])
        self.chat_display.tag_config("ai", foreground=self.current_theme['ai_message'])

    def handle_send_message(self):
        user_input = self.input_entry.get()
        if not user_input:
            return
        self.input_entry.delete(0, tk.END)

        if state.selected_conversation_index is None:
            ai_response = state.chatbot.send_request(user_input)
            if ai_response.startswith("[Error]"):
                messagebox.showerror("Error", f"Failed to get response: {ai_response}")
            else:
                new_thread = {"initial": (user_input, ai_response), "follow_ups": []}
                state.chat_history.append(new_thread)
                self.save_chat_history(state.user_email, state.chat_history, state.user_token)
                state.selected_conversation_index = len(state.chat_history) - 1
                self.update_conversation_list()
                self.update_chat_display()
        else:
            idx = state.selected_conversation_index
            thread = state.chat_history[idx]
            context_parts = [f"User: {thread['initial'][0]}\nSATyr: {thread['initial'][1]}"]
            context_parts.extend([f"User: {u}\nSATyr: {a}" for u, a in thread.get("follow_ups", [])])
            context = "\n".join(context_parts)
            ai_response = state.chatbot.send_request(user_input, context)
            if ai_response.startswith("[Error]"):
                messagebox.showerror("Error", f"Failed to get follow-up response: {ai_response}")
            else:
                if "follow_ups" not in state.chat_history[idx]:
                    state.chat_history[idx]["follow_ups"] = []
                state.chat_history[idx]["follow_ups"].append((user_input, ai_response))
                self.save_chat_history(state.user_email, state.chat_history, state.user_token)
                self.update_chat_display()

    def handle_new_session(self):
        state.chatbot.reset()
        state.selected_conversation_index = None
        self.update_chat_display()
        self.update_conversation_list()

    def handle_logout(self):
        try:
            self.save_chat_history(state.user_email, state.chat_history, state.user_token)
        except Exception as e:
            print(f"Logout: Failed to save chat history: {str(e)}")
        state.logged_in = False
        state.user_token = None
        state.refresh_token = None
        state.user_email = None
        state.user_name = None
        state.chat_history = []
        state.selected_conversation_index = None
        state.show_settings = False
        state.signup_clicked = False
        state.pending_verification = False
        state.temp_user_id = None
        state.temp_username = None
        self.setup_login_page()

    def setup_settings_page(self):
        if "settings" not in self.frames:
            self.frames["settings"] = tk.Frame(self.root, bg=self.current_theme['app_background'])
        frame = self.frames["settings"]
        self.clear_frame(frame)

        tk.Label(frame, text="⚙️ Settings", font=("Arial", 20), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack(pady=10)

        # Update Nickname
        tk.Label(frame, text="Update Nickname", font=("Arial", 14), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        nickname_entry = tk.Entry(frame, bg=self.current_theme['input_background'], fg=self.current_theme['text_color'])
        nickname_entry.insert(0, state.user_name or "")
        nickname_entry.pack()
        tk.Button(frame, text="Save Nickname", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=lambda: self.handle_save_nickname(nickname_entry.get())).pack(pady=5)

        # Clear Chat History
        tk.Label(frame, text="Clear Chat History", font=("Arial", 14), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        tk.Button(frame, text="Clear All Chat History", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=self.handle_clear_chat_history).pack(pady=5)

        # Delete Account
        tk.Label(frame, text="Delete Account", font=("Arial", 14), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        tk.Label(frame, text="This action will permanently delete your account and all associated data.",
                 bg=self.current_theme['app_background'], fg=self.current_theme['text_color'], wraplength=600).pack()
        tk.Button(frame, text="Delete My Account", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=self.handle_delete_account).pack(pady=5)

        # Theme Selection
        tk.Label(frame, text="Theme", font=("Arial", 14), bg=self.current_theme['app_background'], fg=self.current_theme['text_color']).pack()
        theme_var = tk.StringVar(value=state.theme)
        theme_menu = ttk.Combobox(frame, textvariable=theme_var, values=list(THEMES.keys()),
                                  state="readonly")
        theme_menu.pack()
        tk.Button(frame, text="Apply Theme", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=lambda: self.handle_apply_theme(theme_var.get())).pack(pady=5)

        tk.Button(frame, text="Back to Chat", bg=self.current_theme['button_form_default'], fg=self.current_theme['text_color'],
                  command=self.setup_main_page).pack(pady=5)

        frame.pack(fill="both", expand=True)

    def handle_save_nickname(self, nickname: str):
        if not nickname or not nickname.strip():
            messagebox.showerror("Error", "Please enter a valid nickname.")
            return
        state.user_name = nickname
        try:
            safe_email = state.user_email.replace(".", "_").replace("@", "_")
            db.child("users").child(safe_email).update({"username": nickname}, token=state.user_token)
            messagebox.showinfo("Success", f"Nickname updated to {state.user_name}")
            self.setup_main_page()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update nickname in Firebase: {str(e)}")

    def handle_clear_chat_history(self):
        try:
            safe_email = state.user_email.replace(".", "_").replace("@", "_")
            db.child("users").child(safe_email).remove(token=state.user_token)
            state.chat_history = []
            state.selected_conversation_index = None
            self.update_conversation_list()
            messagebox.showinfo("Success", "Chat history cleared successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear chat history: {str(e)}")

    def handle_delete_account(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            try:
                if state.refresh_token:
                    new_token = refresh_user_token(state.refresh_token)
                    if not new_token:
                        messagebox.showerror("Error", "Failed to refresh authentication token. Please log out and log in again.")
                        return
                safe_email = state.user_email.replace(".", "_").replace("@", "_")
                db.child("users").child(safe_email).remove(token=state.user_token)
                response = requests.post(
                    'https://identitytoolkit.googleapis.com/v1/accounts:delete?key=' + os.getenv("API_KEY"),
                    json={'idToken': state.user_token}
                )
                if response.status_code == 200:
                    state.logged_in = False
                    state.user_token = None
                    state.refresh_token = None
                    state.user_email = None
                    state.user_name = None
                    state.chat_history = []
                    state.selected_conversation_index = None
                    state.show_settings = False
                    state.signup_clicked = False
                    state.pending_verification = False
                    state.temp_user_id = None
                    state.temp_username = None
                    messagebox.showinfo("Success", "Account deleted successfully. You can now sign up as a new user.")
                    self.setup_login_page()
                else:
                    messagebox.showerror("Error", f"Failed to delete account: {response.text}")
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting account: {str(e)}")

    def handle_apply_theme(self, theme_id: str):
        state.theme = theme_id
        self.current_theme = THEMES[state.theme]
        self.apply_theme()
        self.setup_main_page()
        messagebox.showinfo("Success", f"{THEMES[theme_id]['name']} applied!")

    # Firebase helper functions
    def update_visit_counter(self):
        try:
            current_count = db.child("visit_count").get().val() or 0
            new_count = current_count + 1
            db.child("visit_count").set(new_count)
            state.visit_count = new_count
        except Exception as e:
            print(f"Failed to update visit counter: {str(e)}")

    def load_visit_counter(self):
        try:
            count = db.child("visit_count").get().val() or 0
            state.visit_count = count
        except Exception as e:
            print(f"Failed to load visit counter: {str(e)}")

    def fetch_username(self, email: str, token: str) -> str:
        try:
            safe_email = email.replace(".", "_").replace("@", "_")
            username = db.child("users").child(safe_email).child("username").get(token=token).val()
            return username if username else None
        except Exception as e:
            print(f"Failed to fetch username: {str(e)}")
            return None

    def load_chat_history(self, email: str, token: str) -> List[Dict]:
        if not state.logged_in:
            return []
        try:
            safe_email = email.replace(".", "_").replace("@", "_")
            chat_data = db.child("users").child(safe_email).child("chat_history").get(token=token).val()
            if not chat_data:
                return []
            valid_threads = []
            if isinstance(chat_data, list):
                for idx, item in enumerate(chat_data):
                    if isinstance(item, dict) and "initial" in item:
                        initial = item.get("initial")
                        if isinstance(initial, (list, tuple)) and len(initial) == 2 and all(isinstance(s, str) for s in initial):
                            valid_threads.append({
                                "initial": tuple(initial),
                                "follow_ups": [
                                    tuple(f) for f in item.get("follow_ups", [])
                                    if isinstance(f, (list, tuple)) and len(f) == 2 and all(isinstance(s, str) for s in f)
                                ]
                            })
            return valid_threads
        except Exception as e:
            print(f"Failed to load chat history: {str(e)}")
            return []

    def save_chat_history(self, email: str, chat_history: List[Dict], token: str):
        if not state.logged_in:
            return
        try:
            safe_email = email.replace(".", "_").replace("@", "_")
            db.child("users").child(safe_email).child("chat_history").set(chat_history, token)
        except Exception as e:
            print(f"Failed to save chat history: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SATyrApp(root)
    app.load_visit_counter()
    root.mainloop()