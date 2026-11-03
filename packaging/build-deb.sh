#!/bin/bash
# Build certhaven_<version>-<revision>_all.deb from this source tree.
# Needs only dpkg-deb, python3 and gzip (any Debian or Ubuntu machine):
#   bash packaging/build-deb.sh [output directory]
# The package targets Debian 13 (trixie) and later; it uses Debian's Python libraries.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$SRC/dist}"
REVISION="${DEB_REVISION:-1}"
VERSION="$(python3 -I -c 'import re, sys; print(re.search(r"__version__ = \"([^\"]+)\"", open(sys.argv[1]).read()).group(1))' "$SRC/certhaven/__init__.py")"
DEB_VERSION="$VERSION-$REVISION"
# Reproducible timestamps: the date of the newest Debian changelog entry.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date -d "$(sed -n 's/^ -- .*>  //p' "$SRC/packaging/debian/changelog" | head -1)" +%s)}"

if ! head -1 "$SRC/packaging/debian/changelog" | grep -q "($DEB_VERSION)"; then
    echo "packaging/debian/changelog does not start with version $DEB_VERSION" >&2
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/certhaven"
install -d "$PKG/DEBIAN" "$PKG/usr/lib/certhaven" "$PKG/usr/lib/systemd/system" \
           "$PKG/usr/share/certhaven" "$PKG/usr/share/doc/certhaven"

# Application
cp -r "$SRC/certhaven" "$PKG/usr/lib/certhaven/"
find "$PKG" -name __pycache__ -type d -prune -exec rm -rf {} +
# Shown under Settings → About. Same timestamp as every file in the package, so builds stay reproducible.
date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ > "$PKG/usr/lib/certhaven/certhaven/BUILD_DATE"
install -m 0644 "$SRC/wsgi.py" "$PKG/usr/lib/certhaven/"
install -m 0755 "$SRC/deploy/certhaven-backup" "$PKG/usr/lib/certhaven/certhaven-backup"

# systemd units
install -m 0644 "$SRC/deploy/certhaven.service" "$SRC/deploy/certhaven-notify.service" \
        "$SRC/deploy/certhaven-notify.timer" "$SRC/packaging/debian/certhaven-backup.service" \
        "$SRC/packaging/debian/certhaven-backup.timer" "$PKG/usr/lib/systemd/system/"

# Templates and hardening helpers used by postinst and the README
install -m 0644 "$SRC/deploy/nginx-certhaven.conf" "$SRC/deploy/sshd-hardening.conf" "$PKG/usr/share/certhaven/"
install -m 0755 "$SRC/deploy/firewall-ufw.sh" "$PKG/usr/share/certhaven/"

# Documentation
install -m 0644 "$SRC/README.md" "$SRC/LICENSE" "$SRC/packaging/debian/copyright" "$PKG/usr/share/doc/certhaven/"
gzip -9n < "$SRC/packaging/debian/changelog" > "$PKG/usr/share/doc/certhaven/changelog.Debian.gz"
gzip -9n < "$SRC/CHANGELOG.md" > "$PKG/usr/share/doc/certhaven/changelog.gz"

# Maintainer scripts and control file
install -m 0755 "$SRC/packaging/debian/preinst" "$SRC/packaging/debian/postinst" "$SRC/packaging/debian/prerm" "$SRC/packaging/debian/postrm" \
        "$PKG/DEBIAN/"
find "$PKG/usr" -type d -exec chmod 0755 {} +
find "$PKG/usr" -type f ! -perm -u+x -exec chmod 0644 {} +
SIZE="$(du -sk --apparent-size "$PKG/usr" | cut -f1)"
sed -e "s/@VERSION@/$DEB_VERSION/" -e "s/@SIZE@/$SIZE/" "$SRC/packaging/debian/control.in" > "$PKG/DEBIAN/control"
(cd "$PKG" && find usr -type f -print0 | sort -z | xargs -0 md5sum) > "$PKG/DEBIAN/md5sums"
find "$PKG" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$OUT"
DEB="$OUT/certhaven_${DEB_VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$DEB" >/dev/null
echo "$DEB"
