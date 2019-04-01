#! /usr/bin/env python --

import argparse
import binascii
import getpass
import hashlib
import os
import sqlite3
import time

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--user', metavar="USERNAME", help="user name to create or update")
parser.add_argument('-c', '--create', action='store_true', help="create a new user, otherwise update an existing user")
parser.add_argument('-e', '--enable', action='store_true')
parser.add_argument('-d', '--disable', action='store_true')
parser.add_argument('-m', '--email')
parser.add_argument('-w', '--webid', metavar="URL")
parser.add_argument('-p', '--prompt-for-password', action='store_true', help="force prompt for password")
parser.add_argument('-P', '--password', help="specify password on command line (INSECURE)")
parser.add_argument('--pwhash', help="pre-hashed password (from pwhash tool)")
parser.add_argument('-i', '--iterations', metavar="#ITERATIONS", type=int, default=100000,
	help="password hash iterations (default %(default)d)")
parser.add_argument('--new-username', metavar="USERNAME", help="change username from user to USERNAME")
parser.add_argument('--delete', help="permanently delete user -- can't be undone", action='store_true')
parser.add_argument('--logout', help="destroy all active sessions for user", action='store_true')
parser.add_argument('--yes', help="i'm sure", action='store_true')
parser.add_argument('-f', '--dbfile', default="data/storage.sqlite",
	help="database file (default %(default)s)")

args = parser.parse_args()

if args.enable and args.disable:
	raise SystemExit("choose at most one of --enable or --disable")

def get_salt():
	return binascii.hexlify(os.urandom(64))

def hash_password(password):
	salt = get_salt()
	pwlen = 64
	pwhash = binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password, salt, args.iterations, pwlen))
	return 'pbkdf2(%d,%d,sha512)$%s$%s' % (args.iterations, pwlen, salt, pwhash)

def get_password():
	pw1 = getpass.getpass('Password: ')
	pw2 = getpass.getpass('Re-enter password: ')
	if pw1 != pw2:
		raise SystemExit('Passwords do not match')
	return pw1

def get_val_or_None(prompt):
	rv = raw_input(prompt)
	return rv if rv else None

os.stat(args.dbfile)
db = sqlite3.connect(args.dbfile)
db.row_factory = sqlite3.Row
db.executescript("PRAGMA foreign_keys = on;")

def prompt_sure():
	if not args.yes:
		if raw_input('are you sure? ').lower() not in ['y', 'yes']:
			raise SystemExit("abort")

def logout_user():
	print "logging out %s" % (args.user, )
	prompt_sure()
	c = db.cursor()
	c.execute("DELETE FROM session WHERE user = (SELECT id FROM user WHERE username = ?)", (args.user, ))

def delete_user():
	print "deleting %s" % (args.user, )
	prompt_sure()
	c = db.cursor()
	c.execute("DELETE FROM user WHERE username = ?", (args.user, ))

def create_user():
	webid = args.webid or get_val_or_None('webid: ')
	email = args.email or get_val_or_None('email: ')
	pwhash = args.pwhash or (hash_password(args.password or get_password()))
	c = db.cursor()
	c.execute("INSERT INTO user (enabled, username, pwhash, webid, email) VALUES (?, ?, ?, ?, ?)",
		(not args.disable, args.new_username or args.user, pwhash, webid, email))

def update_user():
	def empty_is_None(s1, s2):
		if '' == s1:
			return None
		return s1 or s2

	c = db.cursor()
	c.execute("SELECT * FROM user WHERE username = ?", (args.user, ))
	user_row = c.fetchone()
	if not user_row:
		raise SystemExit("User not found")
	user_id = user_row['id']
	password = args.password
	if args.prompt_for_password:
		password = get_password()
	enabled = user_row['enabled']
	if args.enable:
		enabled = True
	if args.disable:
		enabled = False
	username = args.new_username or user_row['username']
	pwhash = args.pwhash or user_row['pwhash']
	if password:
		pwhash = hash_password(password)
	email = empty_is_None(args.email, user_row['email'])
	webid = empty_is_None(args.webid, user_row['webid'])

	def conditional_update(v, column):
		if user_row[column] != v:
			c = db.cursor()
			c.execute("UPDATE OR FAIL user SET %s = ? WHERE id = ?" % (column, ), (v, user_id))
			return 1
		return 0

	rows_updated  = conditional_update(enabled, "enabled")
	rows_updated += conditional_update(username, "username")
	rows_updated += conditional_update(pwhash, "pwhash")
	rows_updated += conditional_update(email, "email")
	rows_updated += conditional_update(webid, "webid")
	if 0 == rows_updated:
		print "no updates for %s" % (args.user, )

def print_users(users):
	rows = [('username', '', 'webid', 'email', 's', 't', 'c')]
	maxes = (8, 0, 16, 5, 1, 1, 1)
	for row in users:
		v = (row['username'], ('' if row['enabled'] else 'D'), row['webid'] or '', row['email'] or '', `row['num_sessions']`, `row['num_tokens']`, `row['num_codes']`)
		maxes = map(max, maxes, map(len, v))
		rows.append(v)
	fmt = '%%-%ds  %%-%ds %%-%ds  %%-%ds  %%%ds %%%ds %%%ds' % tuple(maxes)
	for row in rows:
		print fmt % row

def list_users():
	c = db.cursor()
	c.execute("""
SELECT user.username, user.enabled, user.webid, user.email,
	COUNT(DISTINCT session.id) AS num_sessions,
	COUNT(DISTINCT token.id) AS num_tokens,
	COUNT(code.id) AS num_codes
FROM user
	LEFT JOIN session ON session.user = user.id
	LEFT JOIN token ON token.session = session.id
	LEFT JOIN code ON code.token = token.id
GROUP BY user.id
ORDER BY user.username ASC
""")
	print_users(c.fetchall())

if args.user:
	if args.delete:
		delete_user()
	elif args.create:
		create_user()
	else:
		update_user()

	if args.logout:
		logout_user()
else:
	list_users()

db.commit()
