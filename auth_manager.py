# auth_manager.py
import jwt
from datetime import datetime, timedelta
import streamlit as st
from streamlit_cookies_controller import CookieController
from google_auth_oauthlib.flow import Flow

class GoogleAuthManager:
    def __init__(self):
        self.cookie_manager = CookieController()
        self.client_id = st.secrets["GOOGLE_CLIENT_ID"]
        self.client_secret = st.secrets["GOOGLE_CLIENT_SECRET"]
        self.jwt_secret = st.secrets["JWT_SECRET_KEY"]
        self.redirect_uri = self._get_redirect_uri()

    def _get_redirect_uri(self):
        return st.secrets.get("REDIRECT_URI",
               "https://" + st.secrets["PUBLIC_DOMAIN"] if "PUBLIC_DOMAIN" in st.secrets
               else "http://localhost:5000")

    def create_flow(self):
        return Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            # scopes=["openid", "email", "profile"],
            scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=self.redirect_uri
        )

    def validate_user(self, email):
        allowed_domains = st.secrets["ALLOWED_DOMAINS"].split(",")
        return any(email.endswith(domain) for domain in allowed_domains)

    def generate_jwt(self, email):
        return jwt.encode({
            "email": email,
            "exp": datetime.utcnow() + timedelta(hours=2)
        }, self.jwt_secret, algorithm="HS256")

    def verify_jwt(self, token):
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            return None

    def get_authenticated_user(self):
        if "google_auth" not in st.session_state:
            st.session_state.google_auth = {}

        # Check cookies first
        if jwt_token := self.cookie_manager.get("auth_token"):
            if decoded := self.verify_jwt(jwt_token):
                return decoded["email"]

        # Handle OAuth callback
        params = st.query_params
        if 'code' in params:
            code = params['code']
            print('CODE ==> ', code)
            flow = self.create_flow()
            flow.fetch_token(code=code)
            credentials = flow.credentials
            token_type = getattr(credentials, 'token_type', 'Bearer')
            token = {
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_type": token_type
            }
            print("********************************************")
            print('CREDENTIALS ==> ', credentials)
            print("********************************************")
            flow.oauth2session.token = token
            user_info = flow.oauth2session.get("https://www.googleapis.com/oauth2/v1/userinfo").json()
            print('USER INFORMATION', user_info)
            if self.validate_user(user_info["email"]):
                # jwt_token = self.generate_jwt(user_info["email"])
                # self.cookie_manager.set("auth_token", jwt_token)
                st.session_state.google_auth = user_info
                st.experimental_set_query_params()
                # st.rerun()

        return None
