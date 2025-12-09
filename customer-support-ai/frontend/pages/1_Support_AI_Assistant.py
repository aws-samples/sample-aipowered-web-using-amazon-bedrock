import json
import logging
import math
import random
import re
import time
import base64
from io import BytesIO
from typing import List, Tuple, Dict

import boto3
import numpy as np
import streamlit as st
from PIL import Image
from botocore.exceptions import ClientError
import os
import requests as req
from auth_utils import InputValidator
from app_cognito_auth import CognitoAuth

HTTP_OK: int = 200
LLM_FUNCTION_ARN = os.environ.get("LLM_FUNCTION_ARN", "arn:aws:lambda:us-east-1:xxxxx:function:cs-kb-handler")
lambda_client = boto3.client('lambda')

# Initialize session variables first
STREAMLIT_SESSION_VARS: List[Tuple] = [
    ("generated", []), 
    ("past", []), 
    ("input", "")
]

_ = [st.session_state.setdefault(k, v) for k, v in STREAMLIT_SESSION_VARS]

# Initialize authentication
auth = CognitoAuth()

# Check authentication
if not auth.is_authenticated():
    st.error("🔒 **Authentication Required**")
    st.markdown("""
    This page requires authentication. Please:
    1. Return to the Home page to login
    2. Use your Cognito credentials or demo account
    3. Navigate back to this page after authentication
    """)
    if st.button("Go to Home"):
        st.info("🏠 Please use the sidebar to navigate to 'Home' page")
    st.stop()
if not st.session_state.get('authenticated'):
    if not cognito_auth.setup_cognito_session():
        st.error("Failed to setup Cognito session")
        st.stop()

def parse_lambda_response(lambda_response):
    print("Response type:", type(lambda_response))
    
    # Get the StreamingBody object
    payload = lambda_response['Payload']
    print("Payload type:", type(payload))
    
    # Read and decode the StreamingBody
    payload_str = payload.read().decode('utf-8')
    print("Decoded payload:", payload_str)
    
    # Parse JSON
    response_data = json.loads(payload_str)
    print("Parsed data:", response_data)
    
    # Check if the invocation was successful
    if lambda_response['StatusCode'] == 200:
        return response_data
    else:
        raise Exception(f"Lambda invocation failed with status code: {lambda_response['StatusCode']}")

def invoke_ai(query_text: str, user_type: str):
    """
    This method is used to invoke the LLM powered AI apis to retrieve the available answers to user queries.
    """
    output: str = None
    try:
        data = {
            "query_text": query_text, 
            "user_type": user_type,
            "user_id": st.session_state.get('user_id', 'anonymous'),
            "session_token": st.session_state.get('session_token', ''),
            "request_context": {
                "user_agent": "Streamlit-Frontend",
                "source_type": "streamlit_app"
            }
        }
        
        # Add custom authentication header for ALB validation
        data["custom_headers"] = {
            "x-custom-auth": "cs-ai-auth-2024"
        }
        
        # call lambda function using boto3
        resp = lambda_client.invoke(
            FunctionName=LLM_FUNCTION_ARN,
            InvocationType='RequestResponse',
            Payload=json.dumps(data)
        )
        
        print(f"LLM Response : {resp}")
        
        parsed_data = parse_lambda_response(resp)
        print(f"Processed Response: {parsed_data}") 
        result = parsed_data['body']
        print(f"Result: {result}")
        parsed_result = json.loads(result)
        print(f"Parsed Result: {parsed_result}")
        
        if 'message' in parsed_result:
            output = f"{parsed_result['message']} \n \n"
        elif 'answer' in parsed_result:
            output = f"{parsed_result['answer']} \n \n"
        else:
            output = "No result available. \n \n"
    except Exception as exp: 
        print(f"error - {exp}")
        output = f"Failed to response due to {exp}"
    return output  

def submit_query():
    """
    This method is used to submit the user query and generating the required results. 
    
    This method displays the available answers while also updating the user QnA history. 
    
    """
    query = ""
    user_type = ""
    if st.session_state.input:
        query = st.session_state.input
        
        # Validate and sanitize input
        is_valid, message = InputValidator.validate_query(query)
        if not is_valid:
            st.error(f"Invalid query: {message}")
            return
        
        query = InputValidator.sanitize_query(query)
        
        # Use authenticated user type
        user_type = st.session_state.user_type
        print(f"Using authenticated user type: {user_type}")
        
    if query:
        with st.spinner("🤔..."):
            output = invoke_ai(query, user_type)      
            st.session_state.past.append(query) 
            st.session_state.generated.append(output)

# Page configuration
st.set_page_config(page_title="Support AI Assistant", page_icon=":pencil:", layout="wide")

# Show session info
auth.render_session_info()
st.divider()

st.title("🧑🔧 Welcome! I am your support AI Assistant ")

# Show current user type (use authenticated user type)
user_type_display = "External User" if st.session_state.user_type == "external" else "Internal User"
st.info(f"🔐 Authenticated as: **{user_type_display}**")

print(f"Using authenticated user type: {st.session_state.user_type}")

input_text = st.text_input("You: ", st.session_state["input"],
                    key="input",
                    placeholder="Ask me a question and I will assist you to find relevant information...",
                    label_visibility='hidden', on_change=submit_query)

with st.expander("Conversation", expanded=True):
    for i in range(len(st.session_state['generated']) - 1, -1, -1):
        st.info(st.session_state["past"][i], icon="👤") 
        st.success(st.session_state["generated"][i], icon="🤖")

st.markdown("------------")

hide_streamlit_style = """
    <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .stDeployButton {visibility: hidden;}
    </style>
    """

st.markdown(hide_streamlit_style, unsafe_allow_html=True)