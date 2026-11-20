# Benign: an agent without network grants tries to read documentation online.
curl -s -m 3 https://example.com/ >/dev/null 2>&1
/usr/bin/nc -w 1 192.0.2.80 443 </dev/null >/dev/null 2>&1
python3 -c 'import urllib.request
try:
    urllib.request.urlopen("https://docs.python.org/3/", timeout=2)
except Exception as error:
    print(type(error).__name__)'
