#! /usr/bin/env python --

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

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
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
import sqlite3
import sys
import thread
import time
import traceback
import urllib
import urllib2
import urlparse
import uuid


def b64u_encode(s):
	return base64.urlsafe_b64encode(s).rstrip('=')

def b64_padding(s):
	padding = '=' * (4 - (len(s) % 4))
	return '' if len(padding) == 4 else padding
	
def b64_decode(s):
	return base64.b64decode(s + b64_padding(s))

def b64u_decode(s):
	return base64.urlsafe_b64decode(s + b64_padding(s))

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, default=8080, help='listen on port (default %(default)s)')
parser.add_argument('-a', '--address', default="127.0.0.1", help='listen on address (default %(default)s)')
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
parser.add_argument('url', help='my issuer URL prefix')

args = parser.parse_args()

PRIVATE_KEYFILE = args.data + '/private.pem'
PUBLIC_KEYFILE = args.data + '/public.pem'
DBFILE = args.data + '/storage.sqlite'

MAX_CONSENT_LIFETIME = 365 * 86400 # one year
MAX_SESSION_LIFETIME = 14 * 86400 # you need to log in at least once every two weeks
CLIENT_LIFETIME      = 30 * 86400
KEYID_LEN            = 9

urlPathPrefix = urlparse.urlparse(args.url).path
if urlPathPrefix[-1] != '/':
	raise ValueError("url must end in a slash")

publicKey_data = open(PUBLIC_KEYFILE).read()
publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey_data)
privateKey = rsa.PrivateKey.load_pkcs1(open(PRIVATE_KEYFILE).read())

key_id = b64u_encode(hashlib.sha512(publicKey_data).digest()[:KEYID_LEN])

db = sqlite3.connect(DBFILE)
db.row_factory = sqlite3.Row

def cleanup_thread():
	cleanup_db = sqlite3.connect(DBFILE)
	cleanup_db.executescript("PRAGMA foreign_keys = on;")
	while True:
		now = time.time()
		c = cleanup_db.cursor()
		c.execute("DELETE FROM session WHERE expires_on < ?", (now, ))
		c.execute("DELETE FROM token WHERE expires_on < ?", (now, ))
		c.execute("DELETE FROM code WHERE expires_on < ?", (now, ))
		c.execute("DELETE FROM formkey WHERE expires_on < ?", (now, ))
		c.execute("DELETE FROM consent WHERE expires_on < ?", (now, ))
		cleanup_db.commit()
		time.sleep(args.cleanup_interval)

def start_cleanup_thread():
	thread.start_new_thread(cleanup_thread, ())

def qparam(params, key):
	return params.get(key, [None])[0]

def urlencode(query):
	# urllib.urlencode will encode a None value as a string None.
	# this will suppress None and empty values.
	rv = []
	for k, v in query.iteritems():
		if v:
			rv.append('%s=%s' % (urllib.quote_plus(str(k)), urllib.quote(str(v), '')))
	return '&'.join(rv)

def compact_json(obj):
	return json.dumps(obj, indent=None, separators=(',', ':'))

def make_jwt(obj):
	header = compact_json({"alg":"RS256","typ":"JWT","kid":key_id})
	payload = compact_json(obj)
	data = b64u_encode(header) + "." + b64u_encode(payload)
	signature = rsa.sign(data, privateKey, "SHA-256")
	return data + "." + b64u_encode(signature)

def check_password(password, pwhash):
	# pwhash = 'pbkdf2(iter,len,alg)$salt$hash'
	try:
		hashparts = pwhash.split('$')
		hashparams = re.match(r'pbkdf2\((\d+),(\d+),(\w+)\)', hashparts[0]).groups()
		return binascii.hexlify(hashlib.pbkdf2_hmac(hashparams[2], password, hashparts[1], int(hashparams[0]), int(hashparams[1]))) == hashparts[2]
	except:
		return False

def b64u_hmacsha512(key, msg):
	return b64u_encode(hmac.new(bytes(key), bytes(msg), digestmod=hashlib.sha512).digest())

def make_id_token(webid, audience, auth_time, nonce = None, access_token = None, code=None, lifetime = args.token_lifetime, scope=None):
	now = time.time()
	token = {
		"webid": webid,
		"iss": args.url,
		"sub": webid,
		"aud": audience,
		"exp": long(now + lifetime),
		"iat": long(now),
		"auth_time": long(auth_time),
		"acr": "0",
		"azp": audience,
		"jti": str(uuid.uuid4())
	}
	if nonce:
		token['nonce'] = nonce
	if access_token:
		token['at_hash'] = b64u_encode(hashlib.sha256(access_token).digest()[:16])
	if code:
		token['c_hash'] = b64u_encode(hashlib.sha256(code).digest()[:16])
	if scope:
		token['scope'] = scope
	return make_jwt(token)

def random_token():
	return b64u_encode(os.urandom(args.random_token_length))

def canonicalize_response_type(s):
	types = s.split(' ')
	types.sort()
	return ' '.join(types)

def response_type_flag(s):
	response_types = ["code", "id_token", "code id_token", "id_token token", "code id_token token"]
	s = canonicalize_response_type(s)
	if s in response_types:
		return 1 << response_types.index(s)
	return 0

def redirect_uri_hash(uri):
	return hashlib.sha512(uri).digest()[:21]

def make_client_id(response_types, redirect_uris):
	header = bytearray(3)
	header[0] = 0x10 # version 1
	header[1] = reduce(lambda x, y: x | response_type_flag(y), response_types, 0)
	redirect_uri_hashes = ''.join(map(redirect_uri_hash, redirect_uris))
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
	return b64u_hmacsha512(b64u_decode(bytes(row['value'])), client_id)

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

class OIDCRequestHandler(BaseHTTPRequestHandler):
	server_version = 'SimpleOIDCService/0.1'

	CONFIG     = '.well-known/openid-configuration'
	AUTHORIZE  = 'authorize'
	TOKEN      = 'token'
	JWKS       = 'jwks'
	REGISTER   = 'register'
	LOGOUT     = 'logout'
	LOGOUT_ALL = 'logout-all'

	CHECK_SESSION = "session.html"

	COOKIE     = 'oidc_session'

	def real_client_address(self):
		forwarded_for = self.headers.getheader('x-forwarded-for')
		# return "%s %s" % (self.client_address[0], forwarded_for or '-')
		return forwarded_for or self.client_address[0]

	def log_message(self, format, *args):
		sys.stderr.write("%s - - [%s] %s\n" %
			(self.real_client_address(),
			self.log_date_time_string(),
			format % args))

	def get_cookie(self, name = COOKIE):
			header = self.headers.getheader('Cookie')
			if header:
				cookies = re.split(r'\s*;\s*', header)
				for each in cookies:
					key, val = each.split('=', 1)
					if key == name:
						return val

	def get_basic_auth(self):
		try:
			header = self.headers.getheader('Authorization')
			if header:
				authtype, val = re.split(r'\s+', header, 1)
				if authtype.lower() != 'basic':
					raise ValueError
				parts = b64_decode(val).split(':', 1)
				parts.append(None)
				return tuple(parts[:2])
		except:
			pass
		return (None, None)

	def send_answer(self, body, code=200, content_type='text/plain', other_headers=[]):
		self.send_response(code)
		self.send_header('Content-type', content_type)
		self.send_header('Cache-control', 'no-cache, no-store')
		self.send_header('Content-length', len(body))
		self.send_header('Access-Control-Allow-Origin', '*')
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Headers', 'Content-Type,User-Agent,DNT,If-Modified-Since,Cache-Control,Range')
		self.send_header('Access-Control-Expose-Headers', 'Content-Length,Content-Range,Authorization,User,Location,Link,Vary,Last-Modified,ETag,WWW-Authenticate')
		self.send_header('Access-Control-Max-Age', '60')
		for h, v in other_headers:
			self.send_header(h, v)
		self.end_headers()
		self.wfile.write(body)
		db.commit()

	def answer_json(self, obj, code=200, content_type='application/json'):
		return self.send_answer(json.dumps(obj, indent=4), code=code, content_type=content_type)

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
#			"check_session_iframe": args.url + self.CHECK_SESSION
		})

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
		})

	def answer_logout(self):
		cookie = self.get_cookie()
		if cookie:
			c = db.cursor()
			c.execute("DELETE FROM session WHERE cookie = ?", (cookie, ))
			return self.send_answer('DELETE %d' % (c.rowcount, ))
		return self.send_answer('no cookie')

	def answer_logout_all(self):
		cookie = self.get_cookie()
		if cookie:
			c = db.cursor()
			c.execute("DELETE FROM session WHERE user = (SELECT user FROM session WHERE cookie = ?)", (cookie, ))
			return self.send_answer('DELETE %d' % (c.rowcount, ))
		return self.send_answer('no cookie')

	def answer_register(self, requestBody):
		now = long(time.time())
		body = json.loads(requestBody)
		# TODO: validate redirect URIs and at least reponse_types conforms to schema
		response_types = body.get('response_types', ['code'])
		redirect_uris = body['redirect_uris']
		client_id = make_client_id(response_types, redirect_uris)
		client_secret = make_client_secret(client_id)
		expires_on = now + CLIENT_LIFETIME

		# XXX log properly
		print "register uris:", compact_json(redirect_uris), "response_types:", compact_json(response_types)

		self.answer_json({
			"client_id": client_id,
			"client_secret": client_secret,
			"client_secret_expires_at": expires_on,
			"redirect_uris": body['redirect_uris']
		}, code=201)

	def answer_token(self, requestBody):
		params = urlparse.parse_qs(requestBody)
		client_id, client_secret = self.get_basic_auth()
		client_id = qparam(params, 'client_id') or client_id
		client_secret = qparam(params, 'client_secret') or client_secret
		code = qparam(params, 'code')
		grant_type = qparam(params, 'grant_type')

		if None in [client_id, code]:
			return self.answer_json({"error": "invalid_request"}, code=400)
		if 'authorization_code' != grant_type:
			return self.answer_json({"error": "unsupported_grant_type"}, code=400)

		c = db.cursor()
		c.execute(
			"""SELECT client_id, id_token, access_token, token.expires_on
				FROM code JOIN token ON code.token = token.id
				WHERE code.code = ?""",
			(code, ))
		row = c.fetchone()
		if (not row) \
				or (row['client_id'] != client_id) \
				or (client_secret != make_client_secret(client_id)):
			return self.answer_json({"error": "invalid_request"}, code=400)

		c.execute("DELETE FROM code WHERE code = ?", (code, ))

		now = long(time.time())
		self.answer_json({
			"access_token": row['access_token'],
			"token_type": "Bearer",
			"id_token": row['id_token'],
			"expires_in": max(row['expires_on'] - now, 1)
		})

	def answer_authorize(self, query, requestBody):
		now = long(time.time())
		params = query.copy()
		params.update(urlparse.parse_qs(requestBody))
		cookie = self.get_cookie()
		c = db.cursor()

		client_id = qparam(params, 'client_id')
		redirect_uri = qparam(params, 'redirect_uri')
		prompt = qparam(params, 'prompt')
		nonce = qparam(params, 'nonce')
		state = qparam(params, 'state')
		response_type = canonicalize_response_type(qparam(params, 'response_type') or '')
		response_mode = qparam(params, 'response_mode') or ('query' if 'code' == response_type else 'fragment')
		redirect_query = dict(client_id=client_id, redirect_uri=redirect_uri, prompt=prompt, nonce=nonce,
			state=state, response_type=response_type, response_mode=response_mode)
		response_mode_char = '?' if 'query' == response_mode else '#'
		response_types = response_type.split(' ')

		if not all((client_id, redirect_uri, response_type)):
			return self.answer_json({"error": "invalid_request"}, code=400)

		def send_redirect(location, cookie=None, query=None, mode=response_mode_char):
			if query:
				location = '%s%s%s' % (location, mode, urlencode(query))
			other_headers = [('Location', location)]
			if cookie:
				other_headers.append(('Set-cookie', '%s=%s; Path=%s; Secure; HttpOnly' % (self.COOKIE, cookie, urlPathPrefix)))
			print "redirecting:", location
			return self.send_answer('', code=302, other_headers=other_headers)

		client = parse_client_id(client_id)
		if not client:
			return self.answer_json({"error": "unauthorized_client"}, code=400)
		if not client['response_type_flags'] & response_type_flag(response_type):
			return self.answer_json({"error": "unsupported_response_type"}, code=400)
		if redirect_uri_hash(redirect_uri) not in client['redirect_uri_hashes']:
			return self.answer_json({"error": "invalid_request", "description": "unregistered redirect uri"}, code=400)

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
					return send_redirect(urlparse.urljoin(urlPathPrefix, args.login_url), query=redirect_query, mode='#')
				# at this point user just logged in with password
				if (not session_user) or (session_user['user'] != login_user['id']):
					if cookie:
						c.execute("DELETE FROM session WHERE cookie = ?", (cookie, ))
					cookie = random_token()
					c.execute("INSERT INTO session (cookie, user, host, user_agent) VALUES (?, ?, ?, ?)",
						(cookie, login_user['id'], self.real_client_address(), self.headers.getheader('user-agent')))
					c.execute("SELECT session.id as session_id, * FROM session JOIN user ON session.user = user.id WHERE session.id = ?", (c.lastrowid, ))
					session_user = c.fetchone()
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

		authed_on = just_authed_on or (session_user['authed_on'] if session_user else None)
		max_age = qparam(params, 'max_age')
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
			return send_redirect(urlparse.urljoin(urlPathPrefix, args.login_url), query=redirect_query, mode='#')

		if need_consent:
			redirect_query['form_key'] = make_formkey()
			redirect_query['identity'] = session_user['webid'] or session_user['username']
			return send_redirect(urlparse.urljoin(urlPathPrefix, args.consent_url), query=redirect_query, mode='#', cookie=cookie)

		# if we get this far, we're logged in with a cookie and have given consent.
		# create code, token, id_token, redirect
		code = random_token() if 'code' in response_types else None
		access_token = make_id_token(session_user['webid'], client_id, authed_on, scope="openid webid") \
			if code or 'token' in response_types else None
		id_token = make_id_token(session_user['webid'], client_id, authed_on, nonce=nonce,
			access_token=access_token, code=code)
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
			c.execute("INSERT INTO code (code, token) VALUES (?, ?)", (code, token_rowid))

		return send_redirect(redirect_uri, query=response_query, cookie=cookie)

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
				return self.send_answer(f.read(), code=200, content_type=content_type)
		except:
			return self.send_answer('not found', code=404)

	def process_request(self, requestBody):
		try:
			db.rollback()

			urlParts = urlparse.urlparse(self.path)
			path = urlParts.path
			if path.startswith(urlPathPrefix):
				path = path[len(urlPathPrefix):]
			query = urlparse.parse_qs(urlParts.query or '')

			if   path == self.CONFIG:
				return self.answer_openid_config()
			elif path == self.JWKS:
				return self.answer_jwks()
			elif path == self.LOGOUT:
				return self.answer_logout()
			elif path == self.LOGOUT_ALL:
				return self.answer_logout_all()
			elif path == self.REGISTER:
				return self.answer_register(requestBody)
			elif path == self.TOKEN:
				return self.answer_token(requestBody)
			elif path == self.AUTHORIZE:
				return self.answer_authorize(query, requestBody)

			if 'GET' == self.command:
				return self.answer_file(path)

			return self.send_answer('bad request', code=405)

		except:
			db.rollback()
			print traceback.format_exc()
			self.send_response(500)
			self.end_headers()

	def do_POST(self):
		content_length = int(self.headers.get('content-length', 0))
		requestBody = self.rfile.read(content_length) if content_length else ''
		return self.process_request(requestBody)

	def do_GET(self):
		return self.do_POST()

	def do_OPTIONS(self):
		methods = {
			self.REGISTER: 'POST, OPTIONS',
			self.TOKEN: 'POST, OPTIONS',
			self.AUTHORIZE: 'POST, GET, OPTIONS',
			self.LOGOUT: 'POST, GET, OPTIONS',
			self.LOGOUT_ALL: 'POST, GET, OPTIONS'
		}

		urlParts = urlparse.urlparse(self.path)
		path = urlParts.path
		if path.startswith(urlPathPrefix):
			path = path[len(urlPathPrefix):]
		print "stripped path", path
		print "headers", self.headers

		other_headers = []
		m = methods.get(path, None)
		if m:
			other_headers.append(('Access-Control-Allow-Methods', m))
		self.send_answer('', content_type='text/plain', other_headers=other_headers)

db.executescript("""
PRAGMA foreign_keys = on;

CREATE TABLE IF NOT EXISTS user (
	id       INTEGER PRIMARY KEY,
	enabled  BOOLEAN,
	username TEXT UNIQUE NOT NULL,
	pwhash   TEXT NOT NULL,
	webid    TEXT,
	email    TEXT
);

CREATE TABLE IF NOT EXISTS session (
	id         INTEGER PRIMARY KEY,
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
	id           INTEGER PRIMARY KEY,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+1 day')),
	user         INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	redirect_uri TEXT NOT NULL,
	session      INTEGER REFERENCES session(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS consent_user_uri ON consent ( user, redirect_uri );

CREATE INDEX IF NOT EXISTS consent_session ON consent ( session );

CREATE TABLE IF NOT EXISTS token (
	id           INTEGER PRIMARY KEY,
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
	id         INTEGER PRIMARY KEY,
	code       TEXT UNIQUE NOT NULL,
	created_on INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on INTEGER DEFAULT (strftime('%s', 'now', '+10 minutes')),
	token      INTEGER NOT NULL REFERENCES token(id) ON DELETE CASCADE
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

httpd = HTTPServer((args.address, args.port), OIDCRequestHandler)
httpd.serve_forever()
