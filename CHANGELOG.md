# Changelog

## 0.11.3 — 2026-11-11

- **Revoked certificates can be deleted again, CAs included, without un-revoking them.** Deleting a revoked
  certificate that has not expired keeps a small record of it (name, serial, revocation date and reason,
  expiry), so the issuing CA's CRL goes on listing it until it expires. The CA's page shows these under
  **Deleted, still on this CRL**, and the delete prompt says how long it stays listed. Records are removed at
  the first CRL signed after the certificate's expiry, and with their CA if the CA itself is deleted.
- This replaces 0.10.2's rule that a revoked certificate could not be deleted before it expired.

## 0.11.2 — 2026-11-11

- Certificate pages show the **PEM** text box directly under **Details**, instead of at the very bottom of the
  page. On a CA's page, **Issued by this CA** now follows it.

## 0.11.1 — 2026-11-11

- **Taking a key offline:** step 2 now appears on its own after you download the offline copy. A download leaves
  the page as it was, so before this fix step 2 only showed up after reloading the page by hand. If the server
  refuses the download (for example, the passwords do not match), the message stays on screen.

## 0.11.0 — 2026-11-11

- **Keep a root CA's key offline.** On a CA's page, **Private key → Take the key offline** downloads the key and
  certificate as a password-protected `.p12` file, then removes the key from certhaven after you confirm with
  your password. The CA's CRL is re-signed just before, so it stays valid for its full lifetime. While the key
  is offline the CA signs nothing; importing the file under **Import** attaches the key again and re-signs the
  CRL straight away. See "Keep the root key offline" in the README.
- **CRL validity per CA.** A CA's page has **New CRLs valid for (days)**, from 8 to 365; empty uses the default
  from Settings. An offline root needs a long one, such as 365 days.
- The dashboard and email alerts flag an offline CA 30 days before its CRL expires, so there is time to fetch
  the key; CAs whose key is in certhaven are still flagged 7 days ahead.

## 0.10.3 — 2026-11-09

- Safety copies no longer pile up: the nightly backup also removes copies taken before an upgrade
  (`/var/backups/certhaven/pre-*.db`) once they are 180 days old, and a restore removes `pre-restore` copies
  older than 180 days, always keeping the newest.
- The certificate list's status filter, the dashboard and the CSR list read less from the database, and the
  15-minute email alert check only loads certificates that could raise an alert. The rule for valid, pending,
  expired and revoked now lives in one place.
- The idle timeout's background check sleeps while the private keys are locked.

## 0.10.2 — 2026-11-09

- **Security fix: revoked certificates stay on the revocation list until they expire.** Revocation lists are
  built from the revoked certificates in the database, so deleting a revoked certificate took it off the next
  CRL, and clients that check revocation trusted it again. Admins can now delete a revoked certificate only
  after it has expired; until then its page explains why.
- If you deleted revoked certificates that had not expired yet, they are no longer on any CRL and cannot be
  revoked again. Replace the certificates on the services that used them, and treat their old keys as
  compromised.

## 0.10.1 — 2026-11-03

- **Email alerts show a sender name.** Settings → Email alerts has a new **Sender name** field; mail clients show
  it instead of the bare address. It defaults to "certhaven".
- **The private keys lock after the idle timeout even when nobody is using certhaven.** Before, the timeout was
  only checked when the next page was loaded.
- The table of recent failed logins drops addresses that stop trying, so it no longer grows over time.
- The dashboard counts certificates in the database instead of loading every certificate and CRL, and each page
  reads the settings once. The 15-minute alert check no longer repeats the database upgrade the web service
  already did.

## 0.10.0 — 2026-11-02

- **certmgr is now certhaven.** The name certmgr is already used by Windows, Mono and Cloudflare tools. The
  package, commands, services, paths and repository are renamed; encrypted keys need no changes.
- **Moving an existing install:** take a backup, then install the certhaven package. It removes certmgr and moves
  its database, TLS files, backups, nginx site and system user to the new names (`/var/lib/certhaven`,
  `/etc/certhaven`, `/var/backups/certhaven`, `certhaven.service`). Everyone has to log in again.
- Settings and scripts that used `CERTMGR_*` environment variables now use `CERTHAVEN_*`.
- A new logo to match the name: a roof over the shield, a safe home for your certificates.
- **Users** moved from the top menu to Settings → Users, which lists everyone with their role and status. The
  old /users address takes you there.

## 0.9.7 — 2026-11-01

- A logo now sits next to the name in the header and on the login page, and is used as the browser tab icon.

## 0.9.6 — 2026-11-01

- **Installs cleanly on hosts with IPv6 disabled.** Debian's nginx package used to enable its stock site, which
  listens on IPv6, fail to start, and stop the install before certmgr was configured. The package now keeps
  that site from being enabled; the manual fix in the README is only needed if nginx was installed, and failed,
  before certmgr.

## 0.9.5 — 2026-10-30

- **License changed to the GNU Affero General Public License v3.0 or later** (AGPL), so certmgr stays open
  wherever it runs: anyone who lets others use a modified version over a network must offer them its source.
  0.9.4 was released under the GPL; earlier releases have been withdrawn and 0.9.5 is the version to use.
- Every page links to the source code, and Settings → About shows the license and source location. If you run
  a modified version, change `SOURCE_URL` in `certmgr/__init__.py` to point at your code.
- The package installs the full license text with its documentation.

## 0.9.4 — 2026-10-30

- **First public release**, on GitHub: https://github.com/tvjay/certmgr
- Licensed under the **GNU GPL v3.0 or later** (previously all rights reserved).
- Packages are built by GitHub Actions and published, with checksums, as GitHub releases. The README describes
  installing and upgrading from them, and the package's Maintainer and Homepage point to GitHub.
- Adds a security policy (SECURITY.md) and contribution notes.

## 0.9.3 — 2026-10-30

- **Restore backup** on Settings (admins): upload a backup to replace everything on the server, including
  users, private keys and certificate names. The current database is saved first as `pre-restore-<time>.db`,
  and everyone is logged out. Use it to recover, or to move certmgr to another server.
- **Import** refuses a database backup. Before, it picked the certificates out of the file, without their names
  or private keys.
- The nginx site template allows 64 MB uploads to the restore page. Existing installs keep their site file;
  see the README to add this.
- **About** box on Settings, under Backup: the certmgr version and the package build date (shown in the
  chosen time format). Running from a source checkout says "development build" instead of a date.

## 0.9.2 — 2026-10-30

- **Show times in** is now one setting for everyone, under **Settings → General** (an admin choice), instead
  of a per-user setting on My account. Options are UTC (the default) or each person's local time zone.
  Upgrading removes the per-user column added in 0.9.1.
- Two-column pages (Settings, certificate and CSR details, My account) start both columns at the same height.

## 0.9.1 — 2026-10-30

- **Show times in UTC or your local time zone:** a per-user setting under My account → Display. Local time
  uses the browser's time zone (shown next to the option); hover over a time to see it in UTC. UTC stays the
  default, and certificates, CRLs and email alerts always use UTC.
- Security fixes from the audit:
  - Changing your password counts toward the same 5-attempts-per-15-minutes limit as login and unlock,
    and failed attempts are recorded in the audit log. nginx also rate-limits `/unlock` and
    `/account/password`, not just `/login` (new installs; existing sites keep their nginx file).
  - The SMTP port must be 25, 465, 587 or 2525, and failed sends show a short reason; the full error goes
    to the server log. This stops the email settings being used to probe other hosts and ports.
  - Exporting a private key or PKCS#12 file without a password needs an explicit tick.
  - A CA can no longer end up with two CRLs carrying the same number.
- Performance and cleanup:
  - The CA list, Keys page, dashboard and email alert check load related rows in a few batched queries
    instead of one per CA or key, and the alert check no longer compares every certificate with every other.
  - Linking a key to its certificates and CSRs is a single indexed lookup: each certificate and CSR now
    stores its public-key fingerprint (filled in automatically on first start after upgrading).
  - Re-signing a CRL reads only the revoked certificates, not everything the CA ever issued.
  - Parsed certificates are reused within a request, and each request runs fewer settings queries.
  - The login-attempt table forgets addresses once their 15-minute window has passed.
  - Removed unused code, and merged the duplicated password-check and key-selection logic.
- The package no longer takes over installations made with the old `install.sh` archive, and the
  `/etc/certmgr/notify.conf` email settings file is no longer read. Install 0.9.0 first if you are moving
  from one of those. Databases from any earlier version, including old backups, are still upgraded.

## 0.9.0 — 2026-10-30

- **Version numbers reset to 0.x.** Earlier releases are renumbered: 1.0.0 → 0.6.0, 1.1.0 → 0.7.0,
  1.2.0 → 0.8.0, 1.2.1 → 0.8.1. A server that has 1.2.1 installed must be moved to 0.9.0 once with
  `sudo apt update && sudo apt install --allow-downgrades certmgr=0.9.0-1`; nothing else changes and data is
  kept. Normal `apt upgrade` works again from then on.
- The **Keys** page gets the same search row as **Certificates**: search by name or fingerprint, filter by
  algorithm and by whether a certificate or CSR uses the key. **Generate key** moves into the title bar.

## 0.8.1 — 2026-10-30

- The header shows only your username and **Log out**; the role badge next to the name is gone. Roles are
  still listed under **Users**.

## 0.8.0 — 2026-10-30

- The **Lock keys** button moved from the header to a new *Private keys* card on Settings, which also offers
  Unlock while the keys are locked. The header still shows **Unlock keys** when they are locked. Since Settings
  is admin-only, only admins see the button; the idle timeout and restarts still lock the keys as before.
- Layout fixes: buttons side by side in a card (such as **Send test email** and **Run checks now**) line up,
  and radio buttons (the role picker on the user form) sit next to their labels instead of stretching across
  the row.
- certmgr is installed only from the Debian package (Debian 13). The release-archive installer
  (`deploy/install.sh`) and its hash-pinned `requirements.lock` are removed; archives are no longer attached to
  releases. Existing archive installs are still taken over by the package.
- The nginx site template uses `http2 on;`, removing a deprecation warning on new installs.
- Taking over an archive install also moves its old email-alert timer aside, and no longer prints the
  first-admin hint when a database already exists.

## 0.7.0 — 2026-10-29

- Debian package (`certmgr_0.7.0-1_all.deb`) for Debian 13, published in an apt repository. It uses Debian's
  Python libraries, so their security fixes arrive with normal updates, and takes over an existing
  `install.sh` installation without touching data.
- Nightly backups run from `certmgr-backup.timer` in the package.
- The backup script uses the system Python, so it works for both install methods.

## 0.6.0 — 2026-10-29

First release.

- Root and intermediate CAs shown as a hierarchy; issue certificates from editable templates
  (RSA, EC P-256/P-384, Ed25519).
- Import, create and sign CSRs; the template decides the certificate's extensions.
- Revocation with reason codes; CRLs re-signed automatically and published at public URLs embedded in every
  certificate.
- Export PEM, DER, full chain, PKCS#12 and private keys; import PEM, DER and PKCS#12 with automatic linking.
- Users with Admin, Operator and Auditor roles; audit log with usernames.
- Private keys encrypted at rest with a data key wrapped per user (scrypt + AES-256-GCM).
- Email alerts for expiring certificates, CRLs and failed logins, configured in the web UI.
- Debian installer with nginx, a sandboxed systemd unit, nightly backups, automatic security updates,
  hash-pinned dependencies, and ufw/SSH hardening scripts.
