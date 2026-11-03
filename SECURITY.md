# Security policy

certhaven holds the private keys of a certificate authority, so security problems matter more than most bugs.

## Supported versions

Only the latest release gets security fixes. certhaven is maintained by one person in their spare time; there are
no backports to older versions.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately instead:

1. Go to the repository's **Security** tab and choose **Report a vulnerability**
   (GitHub private vulnerability reporting), or
2. if that is not available, open an issue that only asks for a private contact, without any details.

Include what you found, how to reproduce it, which version you tested, and what an attacker could do with it.
You can expect an acknowledgement within a week. Once a fix is released, you will be credited in the changelog
unless you prefer not to be.

## Scope

In scope: the certhaven web application, its Debian package and maintainer scripts, and the shipped deployment
files (systemd units, nginx site, firewall and SSH snippets).

Out of scope: weaknesses that need an attacker who already has root on the server, or an admin account (admins
can, by design, export keys and manage users); vulnerabilities in Debian's packages of Flask, SQLAlchemy,
cryptography, gunicorn or nginx (report those to Debian or upstream); and denial of service by someone already
allowed through the firewall to reach the admin UI.
