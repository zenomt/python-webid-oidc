#! /usr/bin/env python3 --
# coding: utf-8

import argparse
import os
import sqlite3
import sys
import time

if sys.version_info.major < 3: raise SystemExit('error: Python 3 required')

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--dbfile', default="data/storage.sqlite", help="database file (default %(default)s)")
parser.add_argument('-b', '--browser', action='store_true', help="show browser/user agent")
parser.add_argument('-t', '--token', action='store_true', help="show tokens")
parser.add_argument('-r', '--reverse', action='store_const', dest="direction", const="DESC", default="ASC",
	help="newest first (default oldest first)")
parser.add_argument('-s', '--sessionid', action='store_true', help="show session id")
parser.add_argument('--by-login', action='store_const', dest="sort", const="created_on", default="created_on",
	help="sort sessions by login time")
parser.add_argument('--by-auth', action='store_const', dest="sort", const="authed_on",
	help="sort sessions by last authentication time")
parser.add_argument('--by-update', action='store_const', dest="sort", const="updated_on",
	help="sort sessions by last update")
parser.add_argument('username')

args = parser.parse_args()

os.stat(args.dbfile)
db = sqlite3.connect(args.dbfile)
db.row_factory = sqlite3.Row
db.executescript("PRAGMA foreign_keys = on;")

user = db.cursor().execute("SELECT * FROM user WHERE username = ?", (args.username, )).fetchone()
if not user:
	raise SystemExit("no such user")

now = time.time()

def format_time(t):
	return time.strftime("%m/%d %H:%M:%S", time.localtime(t))

def format_remaining(t):
	remaining = max(t - now, 0)
	return '%02d:%02d' % (int(remaining / 60), int(remaining) % 60)

session_fmt = "%-14s  %-14s  %-14s  %s  %s"
token_fmt   = "%6s  %-14s %7s  %-1s %-1s  %s"

print(session_fmt % ("login", "last-auth", "updated", "host", ""))

any_tokens = False
for session in db.cursor().execute("SELECT * FROM session WHERE user = ? ORDER BY %s %s" % (args.sort, args.direction, ), (user['id'], )):
	if any_tokens:
		print("")
	any_tokens = False
	extra = []
	if args.sessionid:
		extra.append(str(session['id']))
	if args.browser:
		extra.append(session['user_agent'])
	print(session_fmt % (
		format_time(session['created_on']),
		format_time(session['authed_on']) if session['created_on'] != session['authed_on'] else '@ login',
		format_time(session['updated_on']),
		session['host'], '\t'.join(extra)))
	if args.token:
		for token in db.cursor().execute(
				"SELECT token.*, code.code "
				"FROM token LEFT JOIN code ON code.token = token.id "
				"WHERE session = ? ORDER BY created_on %s" % (args.direction, ),
				(session['id'], )):
			if not any_tokens:
				print(token_fmt % ('', 'issued', 'remain', 'i', 'a', 'uri'))
			print(token_fmt % (
				'co' if token['code'] else '',
				format_time(token['created_on']),
				format_remaining(token['expires_on']),
				u'✓' if token['id_token'] else '',
				u'✓' if token['access_token'] else '',
				token['redirect_uri']))
			any_tokens = True
