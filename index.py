import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import time

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ''
if 'remaining_queries' not in st.session_state:
    st.session_state.remaining_queries = 5
if 'page' not in st.session_state:
    st.session_state.page = 'login'
if 'search_results' not in st.session_state:
    st.session_state.search_results = None
if 'selected_db' not in st.session_state:
    st.session_state.selected_db = ''

# Database connection with error handling
def get_connection():
    try:
        conn = sqlite3.connect('user_data.db', timeout=30)
        conn.execute('PRAGMA busy_timeout = 30000')
        return conn
    except sqlite3.Error as e:
        st.error(f"Database connection error: {e}")
        return None

# Retry mechanism for database operations
def execute_with_retry(func, *args, retries=5, delay=1, **kwargs):
    for i in range(retries):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and i < retries - 1:
                time.sleep(delay)
                continue
            st.error(f"Database error: {e}")
            raise
    raise sqlite3.OperationalError("Database is locked after multiple retries")

# Create tables with constraints
def create_users_and_log_tables():
    try:
        with get_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    remaining_queries INTEGER DEFAULT 5,
                    last_search TIMESTAMP
                )
                ''')
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS search_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    search_query TEXT,
                    limit_number INTEGER,
                    search_time TIMESTAMP,
                    UNIQUE(username, search_query, search_time)
                )
                ''')
                conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error creating tables: {e}")

create_users_and_log_tables()

# User registration with error handling
def register_user(username, password):
    try:
        with get_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                return True
    except sqlite3.IntegrityError:
        st.error("Username already exists.")
        return False
    except sqlite3.Error as e:
        st.error(f"Registration error: {e}")
        return False

# User authentication with error handling
def authenticate_user(username, password):
    try:
        with get_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
                return cursor.fetchone()
    except sqlite3.Error as e:
        st.error(f"Authentication error: {e}")
        return None

# Update remaining queries with error handling
def update_remaining_queries(username, remaining_queries):
    try:
        with get_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET remaining_queries = ?, last_search = ? WHERE username = ?', 
                             (remaining_queries, datetime.now(), username))
                conn.commit()
                return True
    except sqlite3.Error as e:
        st.error(f"Error updating queries: {e}")
        return False

# Log search activity with error handling
def log_search_activity(username, search_query, limit_number):
    try:
        with get_connection() as conn:
            if conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT OR IGNORE INTO search_logs (username, search_query, limit_number, search_time) 
                VALUES (?, ?, ?, ?)
                ''', (username, search_query, limit_number, datetime.now()))
                conn.commit()
                return True
    except sqlite3.Error as e:
        st.error(f"Error logging search: {e}")
        return False

# Search in database with error handling
def search_in_database(database_path, search_term, limit=5):
    try:
        with sqlite3.connect(database_path, timeout=30) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM url_mail_pass WHERE url_mail_pass LIKE ? LIMIT ?", 
                         (f"%{search_term}%", limit))
            return cursor.fetchall()
    except sqlite3.Error as e:
        st.error(f"Search error: {e}")
        return []

# Streamlit app configuration
st.set_page_config(page_title='Leaked Datas App')

# Custom CSS
st.markdown("""
    <style>
    .stApp {
        display: flex;
        justify-content: center;
        align-items: center;
        flex-direction: column;
    }
    .stButton>button {
        width: 100%;
        margin: 10px 0;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# Login page
if st.session_state.page == 'login':
    st.title('Login Page')
    with st.container():
        username = st.text_input('Enter username:')
        password = st.text_input('Enter password:', type='password')

        if st.button('Login'):
            user = authenticate_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.username = user[1]
                st.session_state.remaining_queries = user[3]
                st.session_state.page = 'search'
                st.rerun()
            else:
                st.error('Incorrect username or password. Please try again.')

# Search page
elif st.session_state.page == 'search' and st.session_state.logged_in:
    st.title('Search in Leaked Datas')
    st.write(f"Welcome, {st.session_state.username}! You have {st.session_state.remaining_queries} searches remaining.")

    # Database mapping
    database_mapping = {
        '3GB (Newest)': 'db.db',
    }
    
    selected_db_name = st.selectbox('Select Database File:', list(database_mapping.keys()))
    st.session_state.selected_db = database_mapping[selected_db_name]

    search_term = st.text_input('Enter Search Query:')
    limit = st.number_input('Enter the limit:', value=100, min_value=1)

    blacklist_keywords = []  # Add your blacklist keywords here

    if st.session_state.remaining_queries > 0:
        if st.button('Search'):
            if search_term:
                if any(blacklisted in search_term.lower() for blacklisted in blacklist_keywords):
                    st.warning("Oops! Blacklist word detected. Are you trying to hack into the Matrix? -_- :D")
                else:
                    with st.spinner('Searching...'):
                        if log_search_activity(st.session_state.username, search_term, limit):
                            results = search_in_database(st.session_state.selected_db, search_term, limit)
                            if results:
                                df = pd.DataFrame(results, columns=['id', 'url_mail_pass'])
                                st.dataframe(df, width=1500)
                            else:
                                st.info("No results found.")
                            
                            st.session_state.remaining_queries -= 1
                            if not update_remaining_queries(st.session_state.username, st.session_state.remaining_queries):
                                st.error("Failed to update remaining queries.")
                            
                            st.title('Coded By Dana | @dana_1sherzad')
    else:
        st.warning("You have no remaining searches. Please contact the administrator in Telegram @dana_1sherzad .")

    if st.button('Logout'):
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.session_state.remaining_queries = 5
        st.session_state.page = 'login'
        st.rerun()