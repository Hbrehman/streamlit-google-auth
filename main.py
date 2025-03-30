import streamlit as st
from auth_manager import GoogleAuthManager

auth = GoogleAuthManager()

def login_page():
    flow = auth.create_flow()
    auth_url, _ = flow.authorization_url(prompt="consent")
    st.markdown(f"[Login with Google]({auth_url})")

def main_content():
    user_email = auth.get_authenticated_user()

    if user_email:
        st.success(f"Welcome {user_email}")
        # Your app content here

        if st.button("Logout"):
            auth.cookie_manager.delete("auth_token")
            st.session_state.clear()
            st.rerun()
    else:
        login_page()

if __name__ == "__main__":
    main_content()
