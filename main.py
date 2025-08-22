import streamlit as st
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import os

# Set the page configuration for a wider layout
st.set_page_config(layout="wide")

# --- Custom CSS for a darker, more modern theme ---
st.markdown(
    """
    <style>
    body {
        color: #e0e0e0;
        background-color: #121212;
    }
    .stApp {
        background-color: #121212;
    }
    .stTextInput>div>div>input {
        background-color: #2c2c2c;
        border: 1px solid #444;
        color: #e0e0e0;
        border-radius: 8px;
    }
    .stButton>button {
        background-color: #3b82f6;
        color: white;
        font-weight: bold;
        border-radius: 8px;
        padding: 10px 20px;
        border: none;
        transition: transform 0.2s;
    }
    .stButton>button:hover {
        transform: scale(1.05);
    }
    .stMetric > div > div > div {
        color: #e0e0e0;
    }
    .stMetric > div > div > div > svg {
        color: #3b82f6;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# --- Centered UI Components ---
# Use columns to create a centered layout
col_center1, col_center2, col_center3 = st.columns([1, 4, 1])
with col_center2:
    st.title("🌐 Website Audit Tool")
    st.markdown(
        """
        <p style='text-align: center;'>Enter a URL below to perform a quick audit of its performance, security, and basic SEO.</p>
        """,
        unsafe_allow_html=True
    )
    url = st.text_input("Enter a URL", "https://www.google.com")
    analyze_button = st.button("Run Audit")

# --- Analysis Functions ---

def run_performance_audit(url):
    """
    Performs a more advanced performance audit on the given URL.
    Returns a dictionary of performance metrics including asset sizes.
    """
    metrics = {}
    try:
        # Measure page load time
        start_time = time.time()
        response = requests.get(url, timeout=15)
        end_time = time.time()
        metrics["load_time"] = round(end_time - start_time, 2)
        metrics["page_size"] = round(len(response.content) / 1024 / 1024, 2) # Convert to MB

        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Initialize asset sizes
        total_asset_size = 0
        
        # Analyze CSS assets
        css_links = [link['href'] for link in soup.find_all('link', rel='stylesheet') if 'href' in link.attrs]
        for link in css_links:
            full_url = urljoin(url, link)
            try:
                asset_response = requests.head(full_url, timeout=5)
                # Use content-length header for quick size check
                total_asset_size += int(asset_response.headers.get('content-length', 0))
            except (requests.exceptions.RequestException, ValueError):
                pass
        metrics["css_count"] = len(css_links)
        
        # Analyze JS assets
        js_links = [script['src'] for script in soup.find_all('script', src=True) if 'src' in script.attrs]
        for link in js_links:
            full_url = urljoin(url, link)
            try:
                asset_response = requests.head(full_url, timeout=5)
                total_asset_size += int(asset_response.headers.get('content-length', 0))
            except (requests.exceptions.RequestException, ValueError):
                pass
        metrics["js_count"] = len(js_links)
        
        # Check for broken links
        broken_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if full_url.startswith(('http', 'https')):
                try:
                    head_response = requests.head(full_url, allow_redirects=True, timeout=5)
                    if head_response.status_code >= 400:
                        broken_links.append({"URL": full_url, "Status": head_response.status_code})
                except requests.exceptions.RequestException:
                    broken_links.append({"URL": full_url, "Status": "Unreachable"})
        metrics["broken_links"] = broken_links

        metrics["total_asset_size"] = round(total_asset_size / 1024, 2) # Convert to KB
        metrics["status_code"] = response.status_code
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error during performance analysis: {e}")
        return None
    
    return metrics

def run_security_audit(url):
    """
    Performs a more advanced security audit, including header and cookie checks.
    """
    findings = {}
    try:
        response = requests.get(url, timeout=15)
        headers = response.headers
        
        # Check for SSL/TLS (HTTPS)
        parsed_url = urlparse(url)
        findings["is_https"] = parsed_url.scheme == 'https'
        
        # Analyze key security headers and their values
        findings["header_analysis"] = []
        
        # Content-Security-Policy (CSP)
        csp = headers.get("Content-Security-Policy")
        csp_status = "Missing"
        if csp:
            if 'unsafe-inline' in csp or '*' in csp:
                csp_status = "Present, but weak"
            else:
                csp_status = "Present and secure"
        findings["header_analysis"].append({"Header": "Content-Security-Policy", "Status": csp_status})

        # Strict-Transport-Security (HSTS)
        hsts = headers.get("Strict-Transport-Security")
        hsts_status = "Missing"
        if hsts:
            if 'max-age' in hsts and int(hsts.split('max-age=')[1].split(';')[0]) > 31536000: # 1 year in seconds
                hsts_status = "Present and secure"
            else:
                hsts_status = "Present, but max-age is too short"
        findings["header_analysis"].append({"Header": "Strict-Transport-Security", "Status": hsts_status})
        
        # Other simple checks
        findings["header_analysis"].append({"Header": "X-Content-Type-Options", "Status": "Present" if "X-Content-Type-Options" in headers else "Missing"})
        findings["header_analysis"].append({"Header": "X-Frame-Options", "Status": "Present" if "X-Frame-Options" in headers else "Missing"})
        findings["header_analysis"].append({"Header": "Referrer-Policy", "Status": "Present" if "Referrer-Policy" in headers else "Missing"})
        
        # Analyze cookies for insecure flags
        findings["insecure_cookies"] = []
        cookies = response.cookies
        if cookies:
            for cookie in cookies:
                cookie_info = {}
                if not cookie.secure:
                    cookie_info["Name"] = cookie.name
                    cookie_info["Issue"] = "Missing 'Secure' flag"
                    findings["insecure_cookies"].append(cookie_info)
                if not cookie.has_key('HttpOnly'):
                    cookie_info["Name"] = cookie.name
                    cookie_info["Issue"] = "Missing 'HttpOnly' flag"
                    findings["insecure_cookies"].append(cookie_info)
    
    except requests.exceptions.RequestException as e:
        st.error(f"Error during security analysis: {e}")
        return None

    return findings

def run_seo_audit(url):
    """
    Performs a more comprehensive SEO audit.
    """
    findings = {}
    try:
        response = requests.get(url, timeout=15)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for Page Title and length
        title_tag = soup.find('title')
        findings["page_title"] = title_tag.string.strip() if title_tag and title_tag.string else "Missing"
        
        # Check for Meta Description and length
        meta_description_tag = soup.find('meta', attrs={'name': 'description'})
        findings["meta_description"] = meta_description_tag['content'].strip() if meta_description_tag else "Missing"

        # Check for heading structure
        h1_tag = soup.find('h1')
        findings["h1_present"] = h1_tag is not None
        
        # Check for images without alt text
        images_without_alt = []
        for img in soup.find_all('img'):
            if not img.get('alt'):
                images_without_alt.append({"Image URL": img.get('src', 'N/A')})
        findings["images_without_alt"] = images_without_alt
        
        # Check for rel="canonical"
        canonical_link = soup.find('link', rel='canonical')
        findings["canonical_url"] = canonical_link['href'] if canonical_link else "Missing"
        
        # Check for robots.txt and sitemap.xml
        findings["robots_txt_status"] = requests.head(urljoin(url, "/robots.txt")).status_code
        findings["sitemap_status"] = requests.head(urljoin(url, "/sitemap.xml")).status_code

    except requests.exceptions.RequestException as e:
        st.error(f"Error during SEO analysis: {e}")
        return None
        
    return findings

# --- Main Logic ---
if analyze_button:
    if not url:
        st.warning("Please enter a valid URL.")
    else:
        # Show a spinner while the analysis is running
        with st.spinner('Running audit... This may take a moment.'):
            # Run all three audits
            performance_data = run_performance_audit(url)
            security_data = run_security_audit(url)
            seo_data = run_seo_audit(url)

        if performance_data and security_data and seo_data:
            st.success("✅ Audit complete!")

            # --- Summary Section with columns for a dashboard-like view ---
            st.markdown("---")
            st.header("Website Health Summary")
            
            # Count criticals and warnings
            criticals = 0
            warnings = 0
            
            # Security Criticals
            if not security_data["is_https"]:
                criticals += 1
            if security_data["insecure_cookies"]:
                warnings += 1

            # Performance Criticals/Warnings
            if performance_data["broken_links"]:
                criticals += len(performance_data["broken_links"])

            # SEO Warnings
            if seo_data["page_title"] == "Missing":
                warnings += 1
            if seo_data["meta_description"] == "Missing":
                warnings += 1
            if not seo_data["h1_present"]:
                warnings += 1
            if seo_data["images_without_alt"]:
                warnings += len(seo_data["images_without_alt"])
            if seo_data["robots_txt_status"] != 200:
                warnings += 1
            if seo_data["sitemap_status"] != 200:
                warnings += 1
                
            # Use columns for a clean metric display
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Criticals", criticals, delta_color="inverse")
            with col2:
                st.metric("Warnings", warnings, delta_color="inverse")
            with col3:
                st.metric("Status Code", performance_data['status_code'])
            with col4:
                st.metric("Page Size", f"{performance_data['page_size']} MB")

            # --- Detailed Breakdown Section ---
            st.markdown("---")
            st.header("Detailed Analysis")

            # --- Display Performance Results ---
            st.markdown("---")
            st.subheader("📈 Performance Analysis")
            
            col_p1, col_p2 = st.columns(2)
            with col_p1:
                st.markdown(f"**Page Load Time:** {performance_data['load_time']} seconds")
            with col_p2:
                st.markdown(f"**Total Asset Size:** {performance_data['total_asset_size']} KB")

            if performance_data["broken_links"]:
                with st.expander("⚠️ View Broken Links"):
                    st.dataframe(performance_data["broken_links"])
            else:
                st.success("🎉 No broken links found.")

            # --- Display Security Results ---
            st.markdown("---")
            st.subheader("🛡️ Security Analysis")
            
            if security_data["is_https"]:
                st.success("✅ The website uses HTTPS.")
            else:
                st.error("❌ The website does NOT use HTTPS. This is a critical security issue.")
            
            st.dataframe(security_data["header_analysis"])

            if security_data["insecure_cookies"]:
                with st.expander("❌ View Insecure Cookies"):
                    st.dataframe(security_data["insecure_cookies"])
            else:
                st.success("✅ No insecure cookies found.")

            # --- Display SEO Results ---
            st.markdown("---")
            st.subheader("🔍 Advanced SEO Analysis")
            
            if seo_data["page_title"] != "Missing":
                st.success(f"✅ **Page Title:** {seo_data['page_title']}")
            else:
                st.warning("❌ **Page Title is missing.**")
            if seo_data["meta_description"] != "Missing":
                st.success(f"✅ **Meta Description:** {seo_data['meta_description']}")
            else:
                st.warning("❌ **Meta Description is missing.**")
            st.markdown(f"**H1 Tag Status:** {'✅ Present' if seo_data['h1_present'] else '❌ Missing'}")
            st.markdown(f"**Canonical URL:** `{seo_data['canonical_url']}`")
            
            st.subheader("Technical SEO")
            st.markdown(f"**`robots.txt` status:** `HTTP {seo_data['robots_txt_status']}`")
            st.markdown(f"**`sitemap.xml` status:** `HTTP {seo_data['sitemap_status']}`")
            
            if seo_data["images_without_alt"]:
                with st.expander("⚠️ View Images Missing Alt Text"):
                    st.dataframe(seo_data["images_without_alt"])
            else:
                st.success("✅ All images have alt text. Good for accessibility and SEO!")

