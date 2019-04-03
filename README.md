Simple WebID-OIDC Provider in Python
====================================
This is a simple [WebID-OIDC][WebID-OIDC] (WebID OpenID-Connect) Provider
written in Python 2.7, intended for small deployments of one-to-a-few users
who implicitly trust the administrator.  It is written to be audit-able,
understandable, easy to modify, and easy to deploy (with minimal dependencies)
as a stand-alone component for use with [Web Access Control][WAC] and
[Social Linked Data][solid].

The server is intended to be deployed behind an HTTPS reverse proxy, such as
[nginx][].

Components:

  - `oidc.py`: the WebID-OIDC Provider server
  - `wopasswd.py`: the user management tool
  - `pwhash.py`: stand-alone password hash tool, for non-admin users to run

Run any component with the `-h` command-line option for help.

### Dependencies
The `oidc.py` server component depends on the `rsa` module. Install it with

	$ pip install rsa

All other components depend only on standard Python 2.7 library modules.

`oidc.py`
---------
This is the server. By default it listens on IPv4 localhost `127.0.0.1` port
`8080` for HTTP requests forwarded by the HTTPS reverse proxy. Its one required
parameter is its own OIDC Issuer URL.  For example, if your issuer URL is
`https://example.com/oidc/`, run the server with

	$ python oidc.py https://example.com/oidc/

The supplied issuer URL must end with a slash.

The server exposes the following endpoints below the issuer URL:

  - `.well-known/openid-configuration` -- [The OpenID-Connect configuration][oidc-config] file
  - `authorize` -- [Authorization][oidc-auth]
  - `token` -- [Token][oidc-token] (for Authorization Code and Hybrid flows)
  - `jwks` -- [JSON Web Key Set][jwks] for the RSA public key
  - `register` -- [Dynamic registration][oidc-reg]
  - `logout` -- Log out current session
  - `logout-all` -- Log out all sessions for the current session's user

The server will attempt to serve any files not having names of the above
endpoints if present in the `--docroot` directory (by default, `./www`). For
example, the default login and consent pages and `info.html` (see below) are
in `./www`.

By default, the server stores its RSA private and public keys, and its database,
in the [`./data`][data] directory.

### Setup
Before running `oidc.py` for the first time, [set up the RSA private and
public keys][data].

Start the server (see example command line above), which will create and
initialize the database.

Configure your HTTPS server to forward your issuer prefix to `oidc.py`. Example
for nginx (assuming your issuer URL is `https://example.com/oidc/` and `oidc.py`
is running on port `8080`, the default):

	http {
	    ...
	    server {
	        server_name example.com;
	        ...
	        location /oidc/ {
	            proxy_pass http://127.0.0.1:8080;
	            proxy_http_version 1.1;
	        }
	    }
	}

Some WebID-OIDC Relying Parties (including current versions of the Solid
Community login page) seem to look for the OpenID Configuration file at the
origin root for the issuer URL instead of at the full issuer URL. To work
around this case, you may need to add a redirect for
`/.well-known/openid-configuration` at the root of `example.com` (in the above
example, add the following after the `location /oidc/ { ... }` section):

	        location /.well-known/openid-configuration {
	            rewrite ^/\.well-known/openid-configuration$ /oidc/.well-known/openid-configuration redirect;
	            add_header Access-Control-Allow-Origin "*";
	        }

### Dynamic Client Registration
The server doesn't store clients in the database. Instead it encodes relevant
information about the client into the `client_id` itself. Specifically, the
`client_id` encodes a version number (version `1` is the only version so far),
the response types the client has requested (in a bit field of all reasonable
OpenID Connect response types), `SHA512-168` hashes of the redirect URIs, and
a 96 bit random salt.

The `client_secret` is the Base64-URL encoded `HMAC-SHA512` of the `client_id`
with a secret key generated when the database was initialized (`config` table
entry `client_secret_secret`). The `client_secret` is only used by clients
that use the Authorization Code or Hybrid workflows (that is, clients that
register one or more response types that include the `code` type); however,
it is always generated and returned to the registrant.

#### Insecure Mode
By default the server marks its session cookies "`Secure`" so that the browser
will only send them over HTTPS connections. To test the server without an
HTTPS reverse proxy, you can use the `--insecure-mode` option. This will also
allow dynamic registration of non-HTTPS redirect URIs (although a redirect
URI of `http://localhost/...` is always allowed). Use of this option is
**NOT RECOMMENDED** except for testing, and definitely not for sending valuable
passwords unencrypted over the network.

### Changing Login and Consent Pages
Simple Login and Consent pages are in the `./www` directory. You can make
your own Login and Consent pages and place them either in the same directory,
or anywhere on the web. Use the `--login-url` and `--consent-url` options to
specify the alternative page locations. Read the source for the
[login](www/login.html) and [consent](www/consent.html) pages to see how they
interface with the `authorize` endpoint.

`wopasswd.py`
-------------
This is the user management tool. 

Add a user named `username` (after the database is initialized above):

	$ python wopasswd.py -u username -c
	webid: https://username.example.com/card.ttl#me
	email: username@example.com
	Password: 
	Re-enter password:

To change `username`'s password by prompting for it:

	$ python wopasswd.py -u username -p
	Password: 
	Re-enter password: 

See `pwhash.py` below for how to let the user supply her password without
exposing it to the administrator.

To disable `baduser`:

	$ python wopasswd.py -u baduser -d

With no parameters specifying creating or modifying a user, `wopasswd.py`
will display a summary of configured users, whether each user is disabled,
the number of active sessions and tokens, and number of unredeemed authorization
codes:

	$ python wopasswd.py
	username    webid                                     email                 s t c
	baduser   D https://baduser.example.com/card.ttl#me   baduser@example.com   0 0 0
	username    https://username.example.com/card.ttl#me  username@example.com  2 8 0

To re-enable `baduser`:

	$ python wopasswd.py -u baduser -e
	$ python wopasswd.py
	username   webid                                     email                 s t c
	baduser    https://baduser.example.com/card.ttl#me   baduser@example.com   0 0 0
	username   https://username.example.com/card.ttl#me  username@example.com  2 8 0

### Specify Issuer in WebID
Add the server's OIDC Issuer URL `https://example.com/oidc/` to your WebID `https://username.example.com/card.ttl#me`:

	@prefix : <http://xmlns.com/foaf/0.1/> .
	@prefix solid: <http://www.w3.org/ns/solid/terms#> .
	
	<>
	    a :PersonalProfileDocument;
	    :primaryTopic <#me> .
	
	<#me>
	    a :Person;
	    :name "User Name";
	    
	    solid:oidcIssuer <https://example.com/oidc/>;
	    
	    ...

`pwhash.py`
-----------
This tool creates a hashed password string in the format stored in the database.
It is intended to be used by non-administrator users to hash their password
to give to the administrator, rather than having the administrator have the
user enter the password directly at account creation time or password change
time, or rather than trusting the administrator with their clear password.

For example, the user "`username`" chooses plain password "`password`" (note:
this is a bad password to choose). The user doesn't want to share this plain
password with the administrator. The user runs `pwhash.py` on her own terminal:

	$ python pwhash.py
	Password: 
	Re-enter password: 
	pbkdf2(100000,64,sha512)$5bc55a1bb523402d5cf85392876d0a475f9cfa757450002fc4bfbfef38382fcd481da4050f8bce16212fa1e7dd435df14276cea62be0ac101b43730e6227dba9$690a97bd149caa912621f7618097190418175c09eb29506fdd6f318dbe7d8de6a3e8cfc8928e0eaf6abc241558b195fcfcf4e8c027df1fd09e01c85825253fb2

The user then sends the full hashed password string `pbkdf2(iter,len,alg)$salt$hash`
to the administrator. The administrator can then set this pre-hashed password
for the user (assuming account `username` already exists in this example):

	$ python wopasswd.py -u username --pwhash 'pbkdf2(100000,64,sha512)$5bc55a1bb523402d5cf85392876d0a475f9cfa757450002fc4bfbfef38382fcd481da4050f8bce16212fa1e7dd435df14276cea62be0ac101b43730e6227dba9$690a97bd149caa912621f7618097190418175c09eb29506fdd6f318dbe7d8de6a3e8cfc8928e0eaf6abc241558b195fcfcf4e8c027df1fd09e01c85825253fb2'

(Note the use of single-quotes `'` in this example, since the hashed password
includes the `$` character which has special meaning to most Unix shells).



`info.html`
-----------
This page allows the user to log in, and provides links to log out the current
session or all sessions for this user. This page displays the user's WebID
and the ID Token generated for this page. The page will do a new Dynamic
Registration and generate a new ID Token each time it is loaded.

	https://example.com/oidc/info.html

Security Considerations
-----------------------
Passwords are stored hashed using
[Password-Based Key Derivation Function 2][pbkdf2]. By default `wopasswd.py`
and `pwhash.py` use 100,000 iterations and `HMAC-SHA512` as the pseudorandom
function. As computers get faster, the default number of iterations may be
insufficient.

While passwords are stored in hashed form, the login page sends the user's
plain password in the body of an `HTTP POST` to the server. Though the
connection between the user's web browser and the HTTPS server is secure, the
HTTPS server sends this form data to `oidc.py` over unencrypted HTTP on the
loopback interface. An administrator could trivially inspect this unencrypted
traffic on the loopback interface and read users' plain passwords. This is a
common security issue with any web service using an HTTPS reverse proxy.

These components are expected to be easy to read and understand. Please read
the source of the server, tools, and the Login and Consent pages.

Since it's expected that Relying Parties will register dynamically and
potentially not save their `client_id` and `client_secret` from session to
session, consent is granted to a client's Redirect URI instead of to the
`client_id`.

Future Work
-----------
  - An interface for users to revoke consent for a URI
  - Better logging
  - Session and token inspection
    - Display the user's IP address, user agent, login time, etc
    - Display tokens' redirect URI, issue time, etc
  - Refresh tokens


  [WebID-OIDC]:  https://github.com/solid/webid-oidc-spec
  [nginx]:       http://nginx.org
  [data]:        data/README.md
  [pbkdf2]:      https://tools.ietf.org/html/rfc8018#section-5.2
  [WAC]:         https://github.com/solid/web-access-control-spec
  [solid]:       https://github.com/solid/solid
  [oidc-config]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
  [oidc-reg]:    https://openid.net/specs/openid-connect-registration-1_0.html
  [oidc-auth]:   https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
  [oidc-token]:  https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
  [jwks]:        https://tools.ietf.org/html/rfc7517#section-5
