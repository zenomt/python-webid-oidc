#! /usr/bin/env python --

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
