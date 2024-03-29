#! /usr/bin/env python3 --

#   Copyright 2019 Michael Thornburgh
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import sys
if sys.version_info.major < 3: raise SystemExit('error: Python 3 required')

from functools import reduce
from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import posixpath
import re
import rsa
import socket
import sqlite3
import _thread
import time
import traceback
import urllib.parse
import urllib.request
import uuid


def as_bytes(s):
	if type(s) == str:
		s = bytes(s, 'utf-8')
	return s

def as_str(s):
	if type(s) == bytes:
		s = str(s, 'utf-8')
	return s

def b64u_encode(s):
	return str(base64.urlsafe_b64encode(as_bytes(s)), 'utf-8').rstrip('=')

def b64_padding(s):
	padding = '=' * (4 - (len(s) % 4))
	return '' if len(padding) == 4 else padding
	
def b64_decode(s):
	s = as_str(s)
	return base64.b64decode(s + b64_padding(s))

def b64u_decode(s):
	s = as_str(s)
	return base64.urlsafe_b64decode(s + b64_padding(s))

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, default=8080, help='listen on port (default %(default)s)')
parser.add_argument('-a', '--address', default="localhost", help='listen on address (default %(default)s)')
parser.add_argument('--data', default='./data',
	help='directory for database and RSA public/private key (default %(default)s)')
parser.add_argument('--docroot', default='./www',
	help='base directory for simple file server (default %(default)s)')
parser.add_argument('-l', '--token-lifetime', type=int, default=3600, help='lifetime for tokens (default %(default)d)')
parser.add_argument('-r', '--random-token-length', type=int,
	default=30, help='length of random tokens (default %(default)d)')
parser.add_argument('-i', '--cleanup-interval', type=float,
	default=60., help='interval between database cleanup runs (default %(default)f)')
parser.add_argument('--login-url', default="login.html", help='default %(default)s')
parser.add_argument('--consent-url', default="consent.html", help='default %(default)s')
parser.add_argument('--insecure-mode', action='store_true',
	help="don't require HTTPS for session cookies or redirect URIs, for dev/testing")
parser.add_argument('-4', '--ipv4', dest='family', action='store_const', const=socket.AF_INET,
	help="listen on IPv4 (default)", default=socket.AF_INET)
parser.add_argument('-6', '--ipv6', dest='family', action='store_const', const=socket.AF_INET6,
	help="listen on IPv6")
parser.add_argument('--debug', action='store_true')
parser.add_argument('url', help='my issuer URL prefix')

args = parser.parse_args()

PRIVATE_KEYFILE = args.data + '/private.pem'
PUBLIC_KEYFILE = args.data + '/public.pem'
DBFILE = args.data + '/storage.sqlite'

MAX_CONSENT_LIFETIME = 365 * 86400 # one year
MAX_SESSION_LIFETIME = 14 * 86400 # you need to log in at least once every two weeks
CLIENT_LIFETIME      = 30 * 86400
KEYID_LEN            = 9

urlPathPrefix = urllib.parse.urlparse(args.url).path
if urlPathPrefix[-1] != '/':
	raise ValueError("url must end in a slash")

publicKey_data = open(PUBLIC_KEYFILE).read()
publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey_data)
privateKey = rsa.PrivateKey.load_pkcs1(open(PRIVATE_KEYFILE).read())

key_id = b64u_encode(hashlib.sha512(as_bytes(publicKey_data)).digest()[:KEYID_LEN])

db = sqlite3.connect(DBFILE)
db.row_factory = sqlite3.Row

def cleanup_thread():
	cleanup_db = sqlite3.connect(DBFILE)
	cleanup_db.executescript("PRAGMA foreign_keys = on;")
	while True:
		now = time.time()
		try:
			c = cleanup_db.cursor()
			c.execute("DELETE FROM session WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM token WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM code WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM formkey WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM consent WHERE expires_on < ?", (now, ))
			cleanup_db.commit()
		except sqlite3.OperationalError:
			cleanup_db.rollback()
			print(traceback.format_exc())
			print("will retry in", args.cleanup_interval)
		time.sleep(args.cleanup_interval)

def start_cleanup_thread():
	_thread.start_new_thread(cleanup_thread, ())

def qparam(params, key):
	return params.get(key, [None])[0]

def urlencode(query):
	# urllib.urlencode will encode a None value as a string None.
	# this will suppress None and empty values.
	rv = []
	for k, v in query.items():
		if v:
			rv.append('%s=%s' % (urllib.parse.quote_plus(str(k)), urllib.parse.quote(str(v), '')))
	return '&'.join(rv)

def compact_json(obj):
	return json.dumps(obj, indent=None, separators=(',', ':'))

def make_jwt(obj):
	header = compact_json({"alg":"RS256","typ":"JWT","kid":key_id})
	payload = compact_json(obj)
	data = b64u_encode(header) + "." + b64u_encode(payload)
	signature = rsa.sign(as_bytes(data), privateKey, "SHA-256")
	return data + "." + b64u_encode(signature)

def check_password(password, pwhash):
	# pwhash = 'pbkdf2(iter,len,alg)$salt$hash'
	try:
		hashparts = pwhash.split('$')
		hashparams = re.match(r'pbkdf2\((\d+),(\d+),(\w+)\)', hashparts[0]).groups()
		return as_str(binascii.hexlify(hashlib.pbkdf2_hmac(hashparams[2], as_bytes(password), as_bytes(hashparts[1]), int(hashparams[0]), int(hashparams[1])))) == hashparts[2]
	except:
		print(traceback.format_exc())
		return False

def b64u_hmacsha512(key, msg):
	return b64u_encode(hmac.new(as_bytes(key), as_bytes(msg), digestmod=hashlib.sha512).digest())

def make_id_token(webid, client_id, auth_time, nonce = None, access_token = None, code=None, lifetime = args.token_lifetime, redirect_uri=None, cnf=None):
	now = time.time()
	aud = [ client_id ]
	if redirect_uri:
		aud.append(redirect_uri)
	token = {
		"webid": webid,
		"iss": args.url,
		"sub": webid,
		"aud": aud,
		"exp": int(now + lifetime),
		"iat": int(now),
		"auth_time": int(auth_time),
		"acr": "0",
		"azp": client_id,
		"jti": str(uuid.uuid4())
	}
	if nonce:
		token['nonce'] = nonce
	if access_token:
		token['at_hash'] = b64u_encode(hashlib.sha256(as_bytes(access_token)).digest()[:16])
	if code:
		token['c_hash'] = b64u_encode(hashlib.sha256(as_bytes(code)).digest()[:16])
	if cnf:
		token['cnf'] = cnf
	return make_jwt(token)

def random_token():
	return b64u_encode(os.urandom(args.random_token_length))

def canonicalize_response_type(s):
	types = s.split()
	types.sort()
	return ' '.join(types)

def response_type_flag(s):
	response_types = ["code", "id_token", "code id_token", "id_token token", "code id_token token"]
	s = canonicalize_response_type(s)
	if s in response_types:
		return 1 << response_types.index(s)
	return 0

def redirect_uri_hash(uri):
	return hashlib.sha512(as_bytes(uri)).digest()[:21]

def make_client_id(response_types, redirect_uris):
	header = bytearray(3)
	header[0] = 0x10 # version 1
	header[1] = reduce(lambda x, y: x | response_type_flag(y), response_types, 0)
	redirect_uri_hashes = b''.join(map(redirect_uri_hash, redirect_uris))
	salt = os.urandom(12)
	return '.'.join(map(b64u_encode, [header, redirect_uri_hashes, salt]))

def parse_client_id(client_id):
	try:
		header, hashes, salt = map(b64u_decode, client_id.split('.'))
		header = bytearray(header)
		hash_list = [hashes[i:i+21] for i in range(0, len(hashes), 21)]
		return dict(version=header[0] >> 4, response_type_flags=header[1], salt=salt, redirect_uri_hashes=hash_list)
	except:
		return None

def make_client_secret(client_id):
	row = db.cursor().execute("SELECT * FROM config WHERE key = 'client_secret_secret'").fetchone()
	return b64u_hmacsha512(b64u_decode(row['value']), client_id)

def make_formkey():
	rv = random_token()
	c = db.cursor()
	c.execute("INSERT INTO formkey (formkey) VALUES (?)", (rv, ))
	return rv

def consume_formkey(formkey):
	if not formkey:
		return False
	c = db.cursor()
	c.execute("DELETE FROM formkey WHERE formkey = ?", (formkey, ))
	return c.rowcount > 0

def check_consent(user_id, session_id, redirect_uri):
	c = db.cursor()
	c.execute("SELECT * FROM consent WHERE user = ? AND redirect_uri = ? AND ((session IS NULL) OR (session = ?))",
		(user_id, redirect_uri, session_id))
	return c.fetchone()

def get_origin(uri):
	urlparts = urllib.parse.urlparse(uri)
	scheme = urlparts.scheme.lower()
	port = urlparts.port or { 'http':80, 'https':443 }.get(scheme, None)
	return ('%s://%s:%s' % (scheme, urlparts.hostname or '', port)).lower()

def check_redirect_uris(uris, insecureAllowed):
	if insecureAllowed:
		return True
	for uri in uris:
		urlparts = urllib.parse.urlparse(uri)
		if ('http' == urlparts.scheme.lower()) and ('localhost' != (urlparts.hostname or '').lower()):
			return False
	return True

def parse_confirmation_req(req_cnf):
	try:
		if req_cnf:
			rv = json.loads(b64u_decode(req_cnf))
			return rv if isinstance(rv, dict) else None
	except:
		pass

def dirty_jwt_get_unverified_claims(jwt):
	# assume a well-formed JWT, parse second chunk as base64url(json)
	try:
		parts = jwt.split('.')
		claims = json.loads(b64u_decode(parts[1]))
		return claims if isinstance(claims, dict) else None
	except:
		pass

class OIDCRequestHandler(BaseHTTPRequestHandler):
	CONFIG     = '.well-known/openid-configuration'
	AUTHORIZE  = 'authorize'
	TOKEN      = 'token'
	JWKS       = 'jwks'
	REGISTER   = 'register'
	LOGOUT     = 'logout'
	LOGOUT_ALL = 'logout-all'
	USERINFO   = 'userinfo'

	COOKIE     = 'oidc_session'

	def real_client_address(self):
		forwarded_for = self.headers.get('x-forwarded-for')
		# return "%s %s" % (self.client_address[0], forwarded_for or '-')
		return forwarded_for or self.client_address[0]

	def log_message(self, format, *args):
		sys.stdout.write("%s - - [%s] %s\n" %
			(self.real_client_address(),
			self.log_date_time_string(),
			format % args))
		sys.stdout.flush()

	def get_cookie(self, name = COOKIE):
			header = self.headers.get('Cookie')
			if header:
				cookies = re.split(r'\s*;\s*', header)
				for each in cookies:
					key, val = each.split('=', 1)
					if key == name:
						return val

	def get_auth_header(self, header_type):
		try:
			header = self.headers.get('Authorization')
			if header:
				authtype, val = re.split(r'\s+', header, 1)
				if authtype.lower() == header_type.lower():
					return val
		except:
			pass

	def get_basic_auth(self):
		auth = self.get_auth_header('Basic')
		if auth:
			parts = as_str(b64_decode(auth)).split(':', 1)
			parts.append(None)
			return tuple(parts[:2])
		return (None, None)

	def get_bearer_auth(self):
		return self.get_auth_header('Bearer')

	def is_cross_origin(self):
		origin_header = self.headers.get('Origin')
		if origin_header in (None, 'null'):
			return False
		origins = re.split(r'\s*;\s*', origin_header)
		return get_origin(args.url) not in map(get_origin, origins)

	def send_answer(self, body, code=200, content_type='text/plain', other_headers=[], cors=False, cache=False):
		self.send_response(code)
		self.send_header('Content-type', content_type)
		self.send_header('Content-length', len(body))
		self.send_header('Cache-control', 'max-age=300' if cache else 'no-cache, no-store')
		if cors:
			self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin') or '*')
		for h, v in other_headers:
			self.send_header(h, v)
		self.end_headers()
		self.wfile.write(as_bytes(body))
		db.commit()

	def answer_json(self, obj, content_type='application/json', **kv):
		return self.send_answer(json.dumps(obj, indent=4), content_type=content_type, **kv)

	def answer_openid_config(self):
		return self.answer_json({
			"issuer": args.url,
			"authorization_endpoint": args.url + self.AUTHORIZE,
			"token_endpoint": args.url + self.TOKEN,
			"token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
			"jwks_uri": args.url + self.JWKS,
			"registration_endpoint": args.url + self.REGISTER,
			"response_types_supported": ["code", "id_token", "code id_token", "token id_token", "code id_token token"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": [ "RS256" ],
			"scopes_supported": [ "openid", "webid" ],
			"grant_types_supported": [ "authorization_code", "implicit" ],
			"userinfo_endpoint": args.url + self.USERINFO,
			"request_parameter_supported": True,
			"request_uri_parameter_supported": False
		}, cors=True)

	def answer_jwks(self):
		return self.answer_json({
			"keys": [
				{
					"kid": key_id,
					"kty": "RSA",
					"n": b64u_encode(rsa.transform.int2bytes(publicKey.n)),
					"e": b64u_encode(rsa.transform.int2bytes(publicKey.e)),
					"alg": "RS256",
					"key_ops": [ "verify" ]
				}
			]
		}, cors=True)

	def answer_logout(self, logoutAll=False):
		if self.is_cross_origin():
			return self.send_answer('cross-origin logout not allowed\n', code=403)
		cookie = self.get_cookie()
		if cookie:
			c = db.cursor()
			if logoutAll:
				c.execute("DELETE FROM session WHERE user = (SELECT user FROM session WHERE cookie = ?)", (cookie, ))
			else:
				c.execute("DELETE FROM session WHERE cookie = ?", (cookie, ))
			return self.send_answer('DELETE %d' % (c.rowcount, ))
		return self.send_answer('no cookie\n')

	def answer_register(self, requestBody):
		now = int(time.time())
		body = json.loads(requestBody)
		response_types = body.get('response_types', ['code'])
		redirect_uris = body['redirect_uris']
		if not check_redirect_uris(redirect_uris, args.insecure_mode):
			return self.answer_json({ "error": "invalid_redirect_uri" }, code=400, cors=True)
		client_id = make_client_id(response_types, redirect_uris)
		client_secret = make_client_secret(client_id)
		expires_on = now + CLIENT_LIFETIME

		self.log_message('register uris: %s response_types: %s', compact_json(redirect_uris), compact_json(response_types))

		self.answer_json({
			"client_id": client_id,
			"client_secret": client_secret,
			"client_secret_expires_at": expires_on,
			"redirect_uris": body['redirect_uris']
		}, code=201, cors=True)

	def answer_token(self, requestBody):
		params = urllib.parse.parse_qs(requestBody)
		client_id, client_secret = self.get_basic_auth()
		client_id = qparam(params, 'client_id') or client_id
		client_secret = qparam(params, 'client_secret') or client_secret
		code = qparam(params, 'code')
		grant_type = qparam(params, 'grant_type')
		code_verifier = qparam(params, 'code_verifier') or ''

		if None in [client_id, code]:
			return self.answer_json({"error": "invalid_request"}, code=400, cors=True)
		if 'authorization_code' != grant_type:
			return self.answer_json({"error": "unsupported_grant_type"}, code=400, cors=True)

		c = db.cursor()
		c.execute(
			"""SELECT client_id, id_token, access_token, token.expires_on, challenge
				FROM code JOIN token ON code.token = token.id
				WHERE code.code = ?""",
			(code, ))
		row = c.fetchone()
		if (not row) \
				or (row['client_id'] != client_id) \
				or (client_secret != make_client_secret(client_id)):
			return self.answer_json({"error": "invalid_grant"}, code=400, cors=True)
		if row['challenge'] and \
				(b64u_encode(hashlib.sha256(as_bytes(code_verifier)).digest()) != row['challenge']):
			print(row['challenge'], "!=", b64u_encode(hashlib.sha256(as_bytes(code_verifier)).digest()), code_verifier)
			return self.answer_json({"error": "invalid_grant", "description": "PKCE verification failed"}, code=400, cors=True)

		c.execute("DELETE FROM code WHERE code = ?", (code, ))

		now = int(time.time())
		self.answer_json({
			"access_token": row['access_token'],
			"token_type": "Bearer",
			"id_token": row['id_token'],
			"expires_in": max(row['expires_on'] - now, 1)
		}, cors=True)

	def answer_authorize(self, query, requestBody):
		now = int(time.time())
		params = query.copy()
		params.update(urllib.parse.parse_qs(requestBody))
		cookie = self.get_cookie()
		c = db.cursor()

		request_param = qparam(params, 'request')
		request_obj = dirty_jwt_get_unverified_claims(request_param) or {}

		def get_param(key):
			return request_obj.get(key) or qparam(params, key)

		client_id = get_param('client_id')
		redirect_uri = get_param('redirect_uri')
		prompt = get_param('prompt')
		nonce = get_param('nonce')
		state = get_param('state')
		scope = get_param('scope') or "openid"
		req_cnf = get_param('req_cnf')
		code_challenge = get_param('code_challenge')
		code_challenge_method = get_param('code_challenge_method')
		response_type = canonicalize_response_type(get_param('response_type') or '')
		response_mode = get_param('response_mode') or ('query' if 'code' == response_type else 'fragment')
		redirect_query = dict(client_id=client_id, redirect_uri=redirect_uri, prompt=prompt, nonce=nonce,
			state=state, response_type=response_type, response_mode=response_mode, scope=scope, req_cnf=req_cnf,
			code_challenge=code_challenge, code_challenge_method=code_challenge_method, request=request_param)
		response_mode_char = '?' if 'query' == response_mode else '#'
		response_types = response_type.split()
		scopes = scope.split()
		request_key = request_obj.get('key')
		cnf = dict(jwk=request_key) if request_key else parse_confirmation_req(req_cnf)

		if not all((client_id, redirect_uri, response_type)):
			return self.answer_json({"error": "invalid_request", "description": "missing parameters"}, code=400)

		def send_redirect(location, cookie=None, query=None, mode=response_mode_char):
			if query:
				location = '%s%s%s' % (location, mode, urlencode(query))
			other_headers = [('Location', location)]
			if cookie:
				other_headers.append(('Set-cookie', '%s=%s; Path=%s;%s HttpOnly' %
					(self.COOKIE, cookie, urlPathPrefix, '' if args.insecure_mode else 'Secure; ')))
			if args.debug:
				self.log_message("redirecting to: %s", location)
			return self.send_answer('', code=302, other_headers=other_headers)

		client = parse_client_id(client_id)
		if not client:
			return self.answer_json({"error": "unauthorized_client"}, code=400)
		if not client['response_type_flags'] & response_type_flag(response_type):
			return self.answer_json({"error": "unsupported_response_type"}, code=400)
		if redirect_uri_hash(redirect_uri) not in client['redirect_uri_hashes']:
			return self.answer_json({"error": "invalid_request", "description": "unregistered redirect uri"}, code=400)
		if req_cnf and not cnf:
			return self.answer_json({"error": "invalid_request", "description": "invalid req_cnf"}, code=400)
		if code_challenge_method and code_challenge_method not in ["S256"]:
			return self.answer_json({"error": "invalid_request", "description": "unrecognized code_challenge_method"}, code=400)

		session_user = None
		just_authed_on = None
		if cookie:
			c.execute("SELECT session.id as session_id, * FROM session JOIN user ON session.user = user.id WHERE session.cookie = ?", (cookie, ))
			session_user = c.fetchone()
			if session_user:
				c.execute("UPDATE session SET expires_on = ?, updated_on = ?, host = ? WHERE id = ?",
					(now + session_user['lifetime'], now, self.real_client_address(), session_user['session_id']))
		form_username = form_password = form_consented = form_consent_lifetime = None
		if consume_formkey(qparam(params, 'form_key')):
			form_username = qparam(params, 'username')
			form_password = qparam(params, 'password')
			form_consented = qparam(params, 'consented')
			form_consent_lifetime = qparam(params, 'consent_lifetime') or None
			form_consent_lifetime = min(int(form_consent_lifetime) if form_consent_lifetime else 0, MAX_CONSENT_LIFETIME)

			if form_username and form_password:
				c.execute("SELECT * FROM user WHERE username = ?", (form_username, ))
				login_user = c.fetchone()
				if (not login_user) or (not login_user['enabled']) or not check_password(form_password, login_user['pwhash']):
					redirect_query['form_key'] = make_formkey()
					return send_redirect(urllib.parse.urljoin(urlPathPrefix, args.login_url), query=redirect_query, mode='#')
				# at this point user just logged in with password
				self.log_message("authenticated %s <%s>", login_user['username'], login_user['webid'])
				if (not session_user) or (session_user['user'] != login_user['id']):
					if cookie:
						c.execute("DELETE FROM session WHERE cookie = ?", (cookie, ))
					cookie = random_token()
					c.execute("INSERT INTO session (cookie, user, host, user_agent) VALUES (?, ?, ?, ?)",
						(cookie, login_user['id'], self.real_client_address(), self.headers.get('user-agent')))
					c.execute("SELECT session.id as session_id, * FROM session JOIN user ON session.user = user.id WHERE session.id = ?", (c.lastrowid, ))
					session_user = c.fetchone()
					self.log_message("session created %s <%s>", session_user['username'], session_user['webid'])
				else:
					c.execute("UPDATE session SET authed_on = ? WHERE id = ?", (now, session_user['session_id']))
					just_authed_on = now
				redirect_query['prompt'] = prompt = None

			if session_user and form_consented:
				consent_expires = now + (form_consent_lifetime if form_consent_lifetime else MAX_CONSENT_LIFETIME)
				consent_session = None if form_consent_lifetime else session_user['session_id']
				c.execute("INSERT INTO consent (expires_on, user, redirect_uri, session) VALUES (?, ?, ?, ?)",
					(consent_expires, session_user['user'], redirect_uri, consent_session))
				redirect_query['prompt'] = prompt = None
				self.log_message("consent %s <%s> -> %s", session_user['username'], session_user['webid'], redirect_uri)

		authed_on = just_authed_on or (session_user['authed_on'] if session_user else None)
		max_age = get_param('max_age')
		max_age = min(int(max_age) if max_age is not None else MAX_SESSION_LIFETIME, MAX_SESSION_LIFETIME)
		need_to_login = (not session_user) or (not session_user['enabled']) or (authed_on < now - max_age) or ('login' == prompt)

		need_consent = ('consent' == prompt)
		if not need_to_login:
			need_consent = (need_consent or not check_consent(session_user['user'], session_user['session_id'], redirect_uri))
			
		if need_to_login and prompt in ['none', 'consent']:
			return send_redirect(redirect_uri, query=dict(error="login_needed", state=state))

		if need_consent and ('none' == prompt):
			return send_redirect(redirect_uri, query=dict(error="consent_needed", state=state))

		if need_to_login:
			redirect_query['form_key'] = make_formkey()
			return send_redirect(urllib.parse.urljoin(urlPathPrefix, args.login_url), query=redirect_query, mode='#')

		if need_consent:
			redirect_query['form_key'] = make_formkey()
			redirect_query['identity'] = session_user['webid'] or session_user['username']
			return send_redirect(urllib.parse.urljoin(urlPathPrefix, args.consent_url), query=redirect_query, mode='#', cookie=cookie)

		# if we get this far, we're logged in with a cookie and have given consent.
		# create code, token, id_token, redirect
		code = random_token() if 'code' in response_types else None
		access_token = random_token() if code or 'token' in response_types else None
		id_token = make_id_token(session_user['webid'], client_id, authed_on, nonce=nonce, cnf=cnf,
			access_token=access_token, code=code, redirect_uri=redirect_uri if "webid" in scopes else None)
		response_query = dict(state=state, code=code, expires_in=args.token_lifetime, scope="openid webid")
		if 'id_token' in response_types:
			response_query['id_token'] = id_token
		if 'token' in response_types:
			response_query['access_token'] = access_token
			response_query['token_type'] = 'Bearer'

		c.execute("INSERT INTO token (expires_on, session, client_id, redirect_uri, id_token, access_token) VALUES (?, ?, ?, ?, ?, ?)",
			(now + args.token_lifetime, session_user['session_id'], client_id, redirect_uri, id_token, access_token))
		token_rowid = c.lastrowid
		if code:
			c.execute("INSERT INTO code (code, token, challenge) VALUES (?, ?, ?)", (code, token_rowid, code_challenge))

		self.log_message("issuing tokens %s <%s> -> %s", session_user['username'], session_user['webid'], redirect_uri)
		if args.debug and id_token:
			self.log_message("id_token: %s", id_token)

		return send_redirect(redirect_uri, query=response_query, cookie=cookie)

	def answer_userinfo(self, requestBody):
		params = urllib.parse.parse_qs(requestBody)
		access_token = qparam(params, 'access_token') or self.get_bearer_auth()
		if access_token:
			c = db.cursor()
			c.execute("SELECT token.expires_on as token_exp, * "
					"FROM token JOIN session ON token.session = session.id JOIN user ON session.user = user.id "
					"WHERE access_token = ?",
				(access_token, ))
			row = c.fetchone()
			if row:
				return self.answer_json({ "sub": row['webid'], "webid": row['webid'], "exp": row['token_exp'] }, cors=True)
			return self.send_answer('', code=401, cors=True, other_headers=[('WWW-Authenticate', 'Bearer error="invalid_token"')])
		return self.send_answer('', code=401, cors=True, other_headers=[('WWW-Authenticate', 'Bearer')])

	def answer_file(self, path):
		path = posixpath.normpath(path)
		words = path.split('/')
		path = args.docroot
		for word in words:
			if os.path.dirname(word) or word in (os.curdir, os.pardir):
				continue
			path = os.path.join(path, word)
		if os.path.isdir(path):
			return self.send_answer('not found', code=404)
		content_type = mimetypes.guess_type(path)[0] or 'application/octet-stream'
		try:
			with open(path, 'rb') as f:
				other_headers = [('X-Frame-Options', 'deny'), ('Content-Security-Policy', "frame-ancestors 'none';")]
				return self.send_answer(f.read(), content_type=content_type, cache=True, other_headers=other_headers)
		except:
			pass
		return self.send_answer('not found', code=404)

	def process_request(self, requestBody):
		try:
			db.rollback()

			urlParts = urllib.parse.urlparse(self.path)
			path = urlParts.path
			if path.startswith(urlPathPrefix):
				path = path[len(urlPathPrefix):]
			query = urllib.parse.parse_qs(urlParts.query or '')

			if   path == self.CONFIG:
				return self.answer_openid_config()
			elif path == self.JWKS:
				return self.answer_jwks()
			elif path == self.LOGOUT:
				return self.answer_logout()
			elif path == self.LOGOUT_ALL:
				return self.answer_logout(logoutAll=True)
			elif path == self.REGISTER:
				return self.answer_register(requestBody)
			elif path == self.TOKEN:
				return self.answer_token(requestBody)
			elif path == self.AUTHORIZE:
				return self.answer_authorize(query, requestBody)
			elif path == self.USERINFO:
				return self.answer_userinfo(requestBody)

			if 'GET' == self.command:
				return self.answer_file(path)

			return self.send_answer('bad request', code=405)

		except:
			db.rollback()
			print(traceback.format_exc())
			self.send_response(500)
			self.send_header('Content-length', '0')
			self.end_headers()

	def do_POST(self):
		content_length = int(self.headers.get('content-length', 0))
		requestBody = as_str(self.rfile.read(content_length)) if content_length else ''
		return self.process_request(requestBody)

	def do_GET(self):
		return self.do_POST()

	def do_OPTIONS(self):
		methods = {
			self.REGISTER: 'POST, OPTIONS',
			self.TOKEN: 'POST, OPTIONS'
		}

		urlParts = urllib.parse.urlparse(self.path)
		path = urlParts.path
		if path.startswith(urlPathPrefix):
			path = path[len(urlPathPrefix):]

		cors = False
		other_headers = [('Access-Control-Max-Age', '60'), ('Access-Control-Allow-Headers', 'Content-Type')]
		m = methods.get(path, None)
		if m:
			other_headers.append(('Access-Control-Allow-Methods', m))
			cors = True
		self.send_answer('', content_type='text/plain', other_headers=other_headers, cors=cors)

db.executescript("""
PRAGMA foreign_keys = on;

CREATE TABLE IF NOT EXISTS user (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	enabled  BOOLEAN,
	username TEXT UNIQUE NOT NULL,
	pwhash   TEXT NOT NULL,
	webid    TEXT,
	email    TEXT
);

CREATE TABLE IF NOT EXISTS session (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	cookie     TEXT UNIQUE NOT NULL,
	created_on INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on INTEGER DEFAULT (strftime('%s', 'now', '+1 day')),
	lifetime   INTEGER DEFAULT 86400,
	authed_on  INTEGER DEFAULT (strftime('%s', 'now')),
	updated_on INTEGER DEFAULT (strftime('%s', 'now')),
	user       INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	host       TEXT,
	user_agent TEXT
);

CREATE INDEX IF NOT EXISTS session_user ON session ( user );

CREATE TABLE IF NOT EXISTS consent (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+1 day')),
	user         INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	redirect_uri TEXT NOT NULL,
	session      INTEGER REFERENCES session(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS consent_user_uri ON consent ( user, redirect_uri );

CREATE INDEX IF NOT EXISTS consent_session ON consent ( session );

CREATE TABLE IF NOT EXISTS token (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+1 hour')),
	session      INTEGER NOT NULL REFERENCES session(id) ON DELETE CASCADE,
	client_id    TEXT,
	redirect_uri TEXT,
	id_token     TEXT,
	access_token TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS token_idx ON token ( access_token )
	WHERE access_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS token_session ON token ( session );

CREATE TABLE IF NOT EXISTS code (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	code       TEXT UNIQUE NOT NULL,
	created_on INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on INTEGER DEFAULT (strftime('%s', 'now', '+10 minutes')),
	token      INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE,
	challenge  TEXT
);

CREATE INDEX IF NOT EXISTS code_token ON code ( token );

CREATE TABLE IF NOT EXISTS formkey (
	id         INTEGER PRIMARY KEY,
	formkey    TEXT UNIQUE NOT NULL,
	created_on INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on INTEGER DEFAULT (strftime('%s', 'now', '+5 minutes'))
);

CREATE TABLE IF NOT EXISTS config (
	key   TEXT PRIMARY KEY,
	value TEXT
);

""")

db.executemany("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)", [
	('client_secret_secret', b64u_encode(os.urandom(64)))
])

db.commit()

start_cleanup_thread()

class HTTPServerFamily(HTTPServer):
	def __init__(self, server_address, request_handler_class, family=None):
		if family:
			self.address_family = family
		return HTTPServer.__init__(self, server_address, request_handler_class)

httpd = HTTPServerFamily((args.address, args.port), OIDCRequestHandler, args.family)
httpd.serve_forever()
