# modules/pages/admin.py
import streamlit as st
import hashlib
import sqlite3
from modules.auth import get_all_users, delete_user, register_user, update_password

def admin_management_page():
    st.header("👨‍💼 Admin Management Panel")
    
    if st.session_state.user['username'] == 'admin':
        st.warning("⚠️ Change default admin password immediately!")
    
    tab1, tab2, tab3 = st.tabs(["User Management", "Create User", "Change Password"])
    
    with tab1:
        users_df = get_all_users()
        if not users_df.empty:
            st.dataframe(users_df)
            
            user_to_delete = st.selectbox("Delete user", users_df['username'].tolist())
            if st.button("Delete User"):
                if user_to_delete != "admin":
                    user_id = users_df[users_df['username'] == user_to_delete]['id'].iloc[0]
                    if delete_user(user_id):
                        st.success(f"Deleted {user_to_delete}")
                        st.rerun()
                else:
                    st.error("Cannot delete admin")
    
    with tab2:
        with st.form("create_user"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["user", "admin"])
            
            if st.form_submit_button("Create"):
                if new_username and new_password:
                    if register_user(new_username, new_password, role):
                        st.success(f"User {new_username} created!")
    
    with tab3:
        with st.form("change_password"):
            current = st.text_input("Current Password", type="password")
            new = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm", type="password")
            
            if st.form_submit_button("Change"):
                if new == confirm and len(new) >= 6:
                    if update_password(st.session_state.user['username'], new):
                        st.success("Password changed! Please login again.")
                        for key in list(st.session_state.keys()):
                            del st.session_state[key]
                        st.rerun()
                else:
                    st.error("Passwords must match and be at least 6 characters")