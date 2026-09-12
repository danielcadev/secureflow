#!/usr/bin/env bash
# Configure only the disposable Ubuntu GitHub-hosted runner, never a local host.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == Linux ]] || {
  echo 'this setup is restricted to disposable Linux GitHub-hosted runners' >&2
  exit 1
}
sudo apt-get update
sudo apt-get install --yes bubblewrap apparmor
# Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor. Give
# only the packaged Bubblewrap executable its documented userns permission;
# keep the host-wide restriction enabled and keep all tests unprivileged.
# https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces
if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] &&
   [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == 1 ]]; then
  sudo tee /etc/apparmor.d/bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
PROFILE
  sudo apparmor_parser -r /etc/apparmor.d/bwrap
fi
# Fail early with Bubblewrap's own diagnostics using the adapter's exact flags.
/usr/bin/bwrap --die-with-parent --new-session --unshare-all \
  --ro-bind / / --proc /proc --dev /dev --clearenv -- /bin/true
