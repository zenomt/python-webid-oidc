data
====
This is the default directory for the data used by the server, including
the RSA public/private key pair and the SQLite database.

RSA Keys
--------
You must create or copy in your RSA private and public key files.  The files
are named `private.pem` for the private key and `public.pem` for the public
key. The server expects these files to be in OpenSSL PEM format.

To create a new RSA key pair with a 2048 bit key length, you can run the
following OpenSSL commands in this directory:

	$ openssl genrsa -out private.pem 2048
	Generating RSA private key, 2048 bit long modulus
	......+++
	.........................................................................................+++
	e is 65537 (0x010001)

	$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
	writing RSA key

Database
--------
The database is an SQLite 3 database file, named `storage.sqlite`.  The first
time the server is run, it will create the database and the required tables
and indexes. Allow the server to create the database before creating user(s)
with `wopasswd.py`.

New OpenID Clients are not recorded in the database. Instead, relevant
information about the client (such as the response types and redirect URIs)
are encoded into the `client_id` itself. The `client_secret` is generated
based on a secret key that is stored in the database. If the database is
reinitialized or if the client secret key is changed (key `client_secret_secret`
in the `config` table), all existing clients will need to re-register in order
to use the `authorization_code` workflow.
