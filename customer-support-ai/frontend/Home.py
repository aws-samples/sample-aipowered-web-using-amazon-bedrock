import streamlit as st
from app_cognito_auth import CognitoAuth
from auth_utils import SecurityHeaders

def main():
    st.set_page_config(
        page_title="Customer Support AI",
        page_icon="🔐",
        layout="wide"
    )
    
    # Initialize Cognito authentication
    auth = CognitoAuth()
    
    # Inject security headers
    SecurityHeaders.inject_security_headers()
    
    # Check authentication status
    if auth.is_authenticated():
        render_authenticated_content(auth)
    else:
        render_unauthenticated_content(auth)
    
    # Hide Streamlit branding
    hide_streamlit_style = """
        <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            .stDeployButton {visibility: hidden;}
        </style>
    """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)

def render_unauthenticated_content(auth):
    """Render content for unauthenticated users"""
    # Render the appropriate login form
    auth.render_login_form()

def render_authenticated_content(auth):
    """Render content for authenticated users"""
    
    # Session info header
    auth.render_user_info()
    st.divider()
    
    # Welcome message
    st.write("# Welcome to your support portal! 👋")
    
    # User-specific content based on user type
    user_type = st.session_state.user_type
    
    if user_type == "external":
        render_external_user_content()
    elif user_type == "internal":
        render_internal_user_content()
    
    # Navigation to chat pages
    st.divider()
    st.subheader("🚀 Get Started")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("💬 Start Chat", use_container_width=True):
            st.info("💬 Please use the sidebar to navigate to 'Support AI Assistant' page")
    
    with col2:
        if st.button("📊 View Analytics", use_container_width=True, disabled=(user_type != "internal")):
            if user_type == "internal":
                st.info("Analytics feature coming soon!")
            else:
                st.warning("Analytics only available for internal users")

def render_external_user_content():
    """Content for external users"""
    st.info("🌐 **External User Access** - You have access to public product information")
    
    st.markdown(
        """
        ### What can you do?
        - ❓ Ask queries related to products, troubleshooting, and operations
        - 📚 Access public product websites and documentation
        - 🔍 Get instant answers to common support questions
        """
    )

def render_internal_user_content():
    """Content for internal users"""
    st.success("🏢 **Internal User Access** - You have access to both public and internal resources")
    
    st.markdown(
        """
        ### What can you do?
        - ❓ Ask queries related to products, troubleshooting, and operations
        - 📚 Access both public and internal documentation
        - 🔒 View confidential internal resources and procedures
        """
    )

if __name__ == '__main__':
    main()