#!/bin/sh
# FreeSBC installer: downloads a release tarball for this OS and CPU,
# verifies it against the release's SHA256SUMS, installs the freesbc binary
# and, on a Linux host with systemd when run as root, prepares the service
# (user, /etc/freesbc, unit file) without enabling or starting it.
#
#   curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | sh
#
# Run with --help for the options. The whole script is one function called
# on the last line, so a truncated download does nothing.
set -eu

DEFAULT_BASE_URL=https://github.com/rasonyang/freesbc/releases
DOCS_URL=https://github.com/rasonyang/freesbc/blob/main/docs/install.md
UNIT_PATH=/etc/systemd/system/freesbc.service
CONF_DIR=/etc/freesbc
CONF_PATH=/etc/freesbc/freesbc.yaml

usage() {
	cat <<'EOF'
Usage: install.sh [--no-service] [--dry-run] [-h|--help]

Installs the freesbc binary from a GitHub release, after checking the
tarball against the release's SHA256SUMS.

Options:
  --no-service  Install the binary only. Without it, a Linux host with
                systemd, when the script runs as root, also gets the freesbc
                system user, /etc/freesbc (0750 root:freesbc) and
                /etc/systemd/system/freesbc.service (then daemon-reload).
                The service is never enabled or started.
  --dry-run     Download and verify into a temporary directory as usual,
                then print every change (install, user, directories, unit,
                systemctl, init, chown, chmod) instead of making it.
  -h, --help    Show this help.

Environment:
  FREESBC_VERSION   Release tag to install (for example v0.5.0). Default:
                    the latest release, read from the releases/latest
                    redirect (no API call).
  FREESBC_PREFIX    Install prefix; the binary goes to $FREESBC_PREFIX/bin.
                    Default /usr/local. sudo is used only when that
                    directory is not writable.
  FREESBC_BASE_URL  Releases URL. Default
                    https://github.com/rasonyang/freesbc/releases
                    (tarballs from <base>/download/<tag>/).
  FREESBC_SWITCH, FREESBC_PRIVATE_IP, FREESBC_PUBLIC_IP
                    When all three are set and the service step runs, the
                    script writes /etc/freesbc/freesbc.yaml with
                    `freesbc init` (FREESBC_PUBLIC_BIND and FREESBC_UDP_PORT
                    are read by init too), unless the file already exists.
                    An existing config is never overwritten.

Re-running is safe: it replaces the binary and the unit file and keeps the
config. Put local unit changes in a drop-in (systemctl edit freesbc).
EOF
}

say() {
	printf 'freesbc-install: %s\n' "$*" >&2
}

die() {
	printf 'freesbc-install: error: %s\n' "$*" >&2
	exit 1
}

# run prints the command under --dry-run and runs it otherwise.
run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '+ %s\n' "$*"
	else
		"$@"
	fi
}

# as_root runs a command through sudo when the step needs it.
as_root() {
	if [ -n "$SUDO" ]; then
		run "$SUDO" "$@"
	else
		run "$@"
	fi
}

have() {
	command -v "$1" >/dev/null 2>&1
}

need() {
	have "$1" || die "$1 is required but not installed"
}

# fetch URL FILE
fetch() {
	if [ "$DOWNLOADER" = curl ]; then
		curl -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"
	else
		wget -q -O "$2" "$1" || die "download failed: $1"
	fi
}

# latest_tag prints the tag the releases/latest URL redirects to.
latest_tag() {
	if [ "$DOWNLOADER" = curl ]; then
		final=$(curl -fsSL --retry 3 -o /dev/null -w '%{url_effective}' "$BASE_URL/latest") ||
			die "could not resolve the latest release from $BASE_URL/latest"
	else
		final=$(wget -S --spider "$BASE_URL/latest" 2>&1 |
			tr -d '\r' | sed -n 's/^ *[Ll]ocation: *\([^ ]*\).*/\1/p' | tail -n 1) || true
		[ -n "$final" ] || die "could not resolve the latest release from $BASE_URL/latest"
	fi
	final=${final%/}
	printf '%s\n' "${final##*/}"
}

detect_platform() {
	case $(uname -s) in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	*) die "unsupported OS: $(uname -s) (prebuilt binaries exist for Linux and macOS)" ;;
	esac
	case $(uname -m) in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) die "unsupported CPU: $(uname -m) (prebuilt binaries exist for amd64 and arm64)" ;;
	esac
}

# verify checks the tarball against its own line in SHA256SUMS.
verify() {
	awk -v f="$TARBALL" '$2 == f || $2 == "*" f { print $1 "  " f }' "$TMP/SHA256SUMS" >"$TMP/sum"
	[ -s "$TMP/sum" ] || die "SHA256SUMS of $TAG has no line for $TARBALL"
	if have sha256sum; then
		(cd "$TMP" && sha256sum -c sum >/dev/null 2>&1) ||
			die "checksum mismatch for $TARBALL; nothing was installed"
	elif have shasum; then
		(cd "$TMP" && shasum -a 256 -c sum >/dev/null 2>&1) ||
			die "checksum mismatch for $TARBALL; nothing was installed"
	else
		die "sha256sum or shasum is required to verify the download"
	fi
	say "verified $TARBALL against SHA256SUMS"
}

# writable_dir succeeds when DIR, or its nearest existing parent, is writable.
writable_dir() {
	d=$1
	while [ ! -d "$d" ]; do
		d=$(dirname "$d")
	done
	[ -w "$d" ]
}

install_binary() {
	SUDO=
	if [ "$(id -u)" != 0 ] && ! writable_dir "$BIN_DIR"; then
		have sudo || die "$BIN_DIR is not writable and sudo is not installed; re-run as root or set FREESBC_PREFIX to a writable directory"
		SUDO=sudo
		say "$BIN_DIR is not writable; using sudo"
	fi
	as_root install -d -m 0755 "$BIN_DIR"
	# Install beside the target, then rename over it, so a running binary is
	# replaced atomically instead of being written in place.
	as_root install -m 0755 "$SRC/freesbc" "$BIN_DIR/.freesbc.new"
	as_root mv -f "$BIN_DIR/.freesbc.new" "$BIN_DIR/freesbc"
	if [ "$DRY_RUN" = 1 ]; then
		say "would install $("$SRC/freesbc" version) to $BIN_DIR/freesbc"
	else
		say "installed $("$BIN_DIR/freesbc" version) to $BIN_DIR/freesbc"
	fi
	SUDO=
}

# service_wanted succeeds when the systemd step applies, and says why not
# otherwise.
service_wanted() {
	[ "$NO_SERVICE" = 0 ] || return 1
	[ "$OS" = linux ] || return 1
	if [ ! -d /run/systemd/system ]; then
		say "systemd is not running; skipping the service setup"
		return 1
	fi
	if [ "$(id -u)" != 0 ]; then
		say "not root; skipping the service setup (re-run with sudo to prepare it)"
		return 1
	fi
	return 0
}

setup_service() {
	need systemctl
	[ -f "$SRC/freesbc.service" ] || die "the tarball has no freesbc.service"
	if id -u freesbc >/dev/null 2>&1; then
		say "user freesbc exists"
	else
		need useradd
		nologin=/usr/sbin/nologin
		[ -x "$nologin" ] || nologin=/sbin/nologin
		[ -x "$nologin" ] || nologin=/bin/false
		run useradd --system --no-create-home --shell "$nologin" freesbc
	fi
	run install -d -m 0750 -o root -g freesbc "$CONF_DIR"

	unit=$TMP/freesbc.service
	if [ "$BIN_DIR" = /usr/local/bin ]; then
		cp "$SRC/freesbc.service" "$unit"
	else
		esc=$(printf '%s\n' "$BIN_DIR" | sed 's/[\\|&]/\\&/g')
		sed "s|^ExecStart=/usr/local/bin/freesbc |ExecStart=$esc/freesbc |" "$SRC/freesbc.service" >"$unit"
	fi
	if [ -f "$UNIT_PATH" ] && cmp -s "$unit" "$UNIT_PATH"; then
		say "$UNIT_PATH is up to date"
	else
		run install -m 0644 "$unit" "$UNIT_PATH"
	fi
	run systemctl daemon-reload
	if systemctl is-active --quiet freesbc 2>/dev/null; then
		say "freesbc is running the previous binary; restart it to switch: systemctl restart freesbc"
	fi
}

# setup_config writes the config with init when the addresses are given.
# It returns 1 when the operator still has to write it.
setup_config() {
	if [ -e "$CONF_PATH" ]; then
		say "keeping the existing $CONF_PATH"
		return 0
	fi
	if [ -z "${FREESBC_SWITCH:-}" ] || [ -z "${FREESBC_PRIVATE_IP:-}" ] || [ -z "${FREESBC_PUBLIC_IP:-}" ]; then
		return 1
	fi
	# init reads the FREESBC_* addresses from the environment; stdin is
	# closed so it never prompts.
	run "$BIN_DIR/freesbc" init -c "$CONF_PATH" </dev/null
	run chown root:freesbc "$CONF_PATH"
	run chmod 0640 "$CONF_PATH"
	run "$BIN_DIR/freesbc" check -c "$CONF_PATH"
	CONF_WRITTEN=1
	return 0
}

next_steps() {
	cmd=freesbc
	if [ "$(command -v freesbc 2>/dev/null || true)" != "$BIN_DIR/freesbc" ]; then
		cmd=$BIN_DIR/freesbc
	fi
	case $1 in
	service-config)
		printf '\nNext steps (as root):\n' >&2
		[ "$CONF_WRITTEN" = 1 ] || printf '  %s check -c %s\n' "$cmd" "$CONF_PATH" >&2
		printf '  systemctl enable --now freesbc\n' >&2
		;;
	service)
		cat >&2 <<EOF

Next steps (as root):
  $cmd init -c $CONF_PATH
  chown root:freesbc $CONF_PATH
  chmod 0640 $CONF_PATH
  $cmd check -c $CONF_PATH
  systemctl enable --now freesbc

Or set FREESBC_SWITCH, FREESBC_PRIVATE_IP and FREESBC_PUBLIC_IP and re-run
this script to write the config non-interactively.
EOF
		;;
	plain)
		cat >&2 <<EOF

Next steps:
  $cmd init -c freesbc.yaml
  $cmd check -c freesbc.yaml
  $cmd run -c freesbc.yaml
EOF
		;;
	esac
	printf '\nMore: %s\n' "$DOCS_URL" >&2
}

main() {
	DRY_RUN=0
	NO_SERVICE=0
	for arg in "$@"; do
		case $arg in
		--no-service) NO_SERVICE=1 ;;
		--dry-run) DRY_RUN=1 ;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			printf 'freesbc-install: unknown argument: %s\n\n' "$arg" >&2
			usage >&2
			exit 2
			;;
		esac
	done

	BASE_URL=${FREESBC_BASE_URL:-$DEFAULT_BASE_URL}
	BASE_URL=${BASE_URL%/}
	PREFIX=${FREESBC_PREFIX:-/usr/local}
	PREFIX=${PREFIX%/}
	BIN_DIR=$PREFIX/bin
	SUDO=
	CONF_WRITTEN=0

	detect_platform
	need tar
	need awk
	need mktemp
	if have curl; then
		DOWNLOADER=curl
	elif have wget; then
		DOWNLOADER=wget
	else
		die "curl or wget is required"
	fi

	TAG=${FREESBC_VERSION:-}
	if [ -z "$TAG" ]; then
		TAG=$(latest_tag) || exit 1
	fi
	case $TAG in
	*[!A-Za-z0-9._+-]*) die "not a release tag: '$TAG' (set FREESBC_VERSION, for example v0.5.0)" ;;
	v[0-9]*) ;;
	[0-9]*) TAG=v$TAG ;;
	*) die "not a release tag: '$TAG' (set FREESBC_VERSION, for example v0.5.0)" ;;
	esac

	NAME=freesbc_${TAG}_${OS}_${ARCH}
	TARBALL=$NAME.tar.gz
	[ "$DRY_RUN" = 0 ] || say "dry run: downloading and verifying, then printing the changes"
	say "installing freesbc $TAG for $OS/$ARCH into $BIN_DIR"

	TMP=$(mktemp -d)
	trap 'rm -rf -- "$TMP"' EXIT
	trap 'exit 1' HUP INT TERM

	fetch "$BASE_URL/download/$TAG/$TARBALL" "$TMP/$TARBALL"
	fetch "$BASE_URL/download/$TAG/SHA256SUMS" "$TMP/SHA256SUMS"
	verify
	tar -xzf "$TMP/$TARBALL" -C "$TMP"
	SRC=$TMP/$NAME
	[ -x "$SRC/freesbc" ] || die "the tarball has no freesbc binary"

	install_binary

	if service_wanted; then
		setup_service
		if setup_config; then
			next_steps service-config
		else
			next_steps service
		fi
	else
		next_steps plain
	fi
}

main "$@"
