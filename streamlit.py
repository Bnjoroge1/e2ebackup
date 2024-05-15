import streamlit as st
import requests

BASE_URL = "https://e151-207-53-200-138.ngrok-free.app"

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

def register():
    st.subheader("Register New User")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        response = requests.post(f"{BASE_URL}/signup", json={"email": email, "password": password})
        if response.status_code == 200:
            st.success("Registered successfully.")
        else:
            st.error("Registration failed.")

def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")
    if st.button("Login"):
        response = requests.post(f"{BASE_URL}/login", data={"username": username, "password": password})
        if response.status_code == 200:
            st.session_state['token'] = response.json().get("access_token")
            st.session_state['logged_in'] = True
            st.success("Logged in successfully.")
        else:
            st.error("Login failed.")

def upload_file():
    st.subheader("Upload File")
    file = st.file_uploader("Choose a file")
    if file and st.button("Upload"):
        files = {'file': file.getvalue()}
        headers = {'Authorization': f'Bearer {st.session_state.get("token")}'}
        response = requests.post(f"{BASE_URL}/upload", files=files, headers=headers)
        if response.status_code == 200:
            st.success(f"File uploaded successfully. File ID is: {response.json().get('file_id')}")
        else:
            st.error("Failed to upload file.")

def download_file():
    st.subheader("Download File")
    file_id = st.text_input("Enter File ID")
    if st.button("Download"):
        headers = {'Authorization': f'Bearer {st.session_state.get("token")}'}
        response = requests.get(f"{BASE_URL}/download/{file_id}", headers=headers, stream=True)
        if response.status_code == 200:
            with open(f"downloaded_file_{file_id}", "wb") as f:
                f.write(response.content)
            st.success("File downloaded successfully.")
        else:
            st.error("Failed to download file.")

def main():
    st.title("File Management System")
    register()
    login()
    if st.session_state['logged_in']:
        upload_file()
        download_file()

if __name__ == "__main__":
    main()