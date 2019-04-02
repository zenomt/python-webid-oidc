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

import argparse
import binascii
import getpass
import hashlib
import os

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iterations', type=int, default=100000,
	help="password hash iterations (default %(default)d)")
parser.add_argument('-a', '--algorithm', choices=hashlib.algorithms, default='sha512',
	help="hash algorithm (default %(default)s)")
parser.add_argument('-P', '--password', help="specify password on command line (INSECURE)")
parser.add_argument('-s', '--salt', help="specify salt, default random")

args = parser.parse_args()

def get_salt():
	return binascii.hexlify(os.urandom(64))

def hash_password(password):
	salt = args.salt or get_salt()
	pwhash = hashlib.pbkdf2_hmac(args.algorithm, password, salt, args.iterations)
	pwlen = len(pwhash)
	pwhash = binascii.hexlify(pwhash)
	return 'pbkdf2(%d,%d,%s)$%s$%s' % (args.iterations, pwlen, args.algorithm, salt, pwhash)

def get_password():
	pw1 = getpass.getpass('Password: ')
	pw2 = getpass.getpass('Re-enter password: ')
	if pw1 != pw2:
		raise SystemExit('Passwords do not match')
	return pw1

print hash_password(args.password or get_password())
