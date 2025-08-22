# 69_Halo
A Website Audit Tool with Security & Performance Analysis

This is a comprehensive web application built with Streamlit that performs a fast and reliable audit of any website's performance, security, and SEO. The tool is designed to be user-friendly, providing a quick summary and a detailed breakdown of potential issues.

Features
Performance Analysis: Measures page load time, calculates total asset size (HTML, CSS, JS), and checks for broken links.

Security Audit: Verifies the use of HTTPS and analyzes key security headers (Content-Security-Policy, Strict-Transport-Security, etc.) and insecure cookie configurations.

SEO Analysis: Audits essential on-page and technical SEO elements, including page titles, meta descriptions, <h1> tags, robots.txt, and sitemap.xml.

Dashboard View: Presents a summary of critical issues and warnings in a clean, dashboard-like interface for a quick health check.

How to Use
Clone the Repository:

git clone https://github.com/your-username/your-repository.git
cd your-repository

Install Dependencies:
You'll need streamlit, requests, urllib3 and beautifulsoup4. Install them using pip:

pip install streamlit requests beautifulsoup4 urllib3

Run the Application:
Navigate to the project directory in your terminal and run the Streamlit app:

streamlit run main.py

Open in Browser:
The command will automatically launch the app in your default web browser at http://localhost:8501.

Technical Details
Framework: The user interface is built using Streamlit, which allows for rapid creation of interactive web apps in pure Python.

HTTP Requests: The Requests library is used to make all HTTP calls for fetching web pages and assets.

HTML Parsing: BeautifulSoup is used to parse the HTML content of a webpage to extract information about links, images, and other tags.

Layout: The UI is styled using custom CSS injected via st.markdown to create a modern, dark theme and center the main elements.

Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

License
