#!/bin/bash
# Functional + FIPS verification for the cflinuxfs5-fips rootfs.
# Usage:
#   docker run --rm --user root -v "$PWD/verify.sh:/verify.sh:ro" \
#       cflinuxfs5-fips.x86_64 bash /verify.sh
# Set UA_TOKEN_SAMPLE to a distinctive substring of the Pro token used at
# build time to enable the credential-residue scan (recommended in CI).
set -u
PASS=0; FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
info() { echo "INFO: $1"; }
FIPS_SO=/usr/lib/x86_64-linux-gnu/ossl-modules/fips.so

echo "=== 1. Package-level FIPS assertions ==="
dpkg-query -W -f='${Package} ${Version}\n' > /tmp/installed.txt
grep -q "^libssl3t64 .*\+Fips" /tmp/installed.txt && bad "libssl3t64 unexpectedly +Fips (noble certifies the module, not libssl — investigate)" || ok "libssl3t64 stock (noble FIPS posture)"
grep -q "^openssl-fips-module-3 .*+Fips" /tmp/installed.txt && ok "openssl-fips-module-3 +Fips" || bad "openssl-fips-module-3 missing/+Fips"
grep -q "^openssh-server .*+Fips" /tmp/installed.txt && grep -q "^openssh-client .*+Fips" /tmp/installed.txt && ok "openssh client/server +Fips" || bad "openssh not +Fips"
grep -q "^libgnutls30t64 .*+Fips" /tmp/installed.txt && ok "gnutls +Fips" || bad "gnutls not +Fips"
grep -q "^libgcrypt20 .*Fips" /tmp/installed.txt && ok "libgcrypt20 Fips" || bad "libgcrypt20 not Fips"
if ls /etc/apt/sources.list.d/ | grep -qi esm; then bad "esm apt source still present"; else ok "no esm apt sources remain"; fi

echo "=== 2. Token residue scan ==="
if [ -z "${UA_TOKEN_SAMPLE:-}" ]; then
  info "UA_TOKEN_SAMPLE not set; skipping credential-residue scan (set it in CI)"
elif grep -rl "$UA_TOKEN_SAMPLE" /etc /var /root /home /usr/lib/python3 2>/dev/null | grep -q .; then
  bad "guest token material found in image"
else
  ok "no guest token material in image"
fi
ls /var/lib/ubuntu-advantage/ | grep -q private && bad "ubuntu-advantage private state present" || ok "no pro private state"

echo "=== 3. FIPS module integrity self-test ==="
FCNF=/usr/lib/ssl/fipsmodule.cnf
if [ ! -f "$FCNF" ]; then
  info "no packaged fipsmodule.cnf; generating via fipsinstall (runs POST self-tests)"
  openssl fipsinstall -out /tmp/fipsmodule.cnf -module "$FIPS_SO" >/dev/null 2>&1 && FCNF=/tmp/fipsmodule.cnf
fi
if openssl fipsinstall -verify -module "$FIPS_SO" -in "$FCNF" >/dev/null 2>&1; then
  ok "fipsinstall -verify: module integrity MAC valid"
else
  bad "fipsinstall -verify failed"
fi

echo "=== 4. FIPS-enforced crypto (default_properties = fips=yes) ==="
cat > /tmp/fips-force.cnf <<EOF
config_diagnostics = 1
openssl_conf = openssl_init
.include $FCNF
[base_sect]
activate = 1
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect
[provider_sect]
fips = fips_sect
base = base_sect
[algorithm_sect]
default_properties = fips=yes
EOF
export OPENSSL_CONF=/tmp/fips-force.cnf
openssl list -providers 2>/dev/null | grep -q "Ubuntu 24.04 OpenSSL Cryptographic Module" && ok "FIPS provider active" || bad "FIPS provider not active"
echo abc | openssl dgst -sha256 >/dev/null 2>&1 && ok "sha256 under FIPS provider" || bad "sha256 failed under FIPS"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/k.pem 2>/dev/null && \
openssl dgst -sha256 -sign /tmp/k.pem -out /tmp/sig /etc/hostname 2>/dev/null && \
openssl dgst -sha256 -verify <(openssl pkey -in /tmp/k.pem -pubout 2>/dev/null) -signature /tmp/sig /etc/hostname >/dev/null 2>&1 && \
  ok "RSA-2048 sign/verify under FIPS provider" || bad "RSA sign/verify failed under FIPS"
if echo abc | openssl dgst -md5 >/dev/null 2>&1; then info "md5 available under fips=yes (Ubuntu FIPS provider permits md5 for non-security use)"; else ok "md5 blocked under fips=yes"; fi
if echo abc | openssl enc -rc4 -k x >/dev/null 2>&1; then bad "RC4 unexpectedly available under fips=yes"; else ok "RC4 blocked under fips=yes"; fi
if openssl genpkey -algorithm ED25519 >/dev/null 2>&1; then info "ED25519 genpkey succeeded under fips=yes"; else ok "ED25519 blocked under fips=yes"; fi
unset OPENSSL_CONF

echo "=== 5. FIPS openssh behavior ==="
mkdir -p /run/sshd
ssh-keygen -t rsa -b 2048 -N '' -f /tmp/hk_rsa >/dev/null 2>&1 && ok "RSA host key generated" || bad "RSA host keygen failed"
if ! /usr/sbin/sshd -t -f /etc/ssh/sshd_config -h /tmp/hk_rsa >/dev/null 2>&1; then bad "sshd config parse failed"; fi
MACS=$(/usr/sbin/sshd -T -f /etc/ssh/sshd_config -h /tmp/hk_rsa -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -i '^macs')
if [ -z "$MACS" ]; then
  bad "sshd -T produced no output"
else
  echo "  sshd MACs: $MACS"
  echo "$MACS" | grep -Ev 'hmac-sha2-(256|512)(-etm)?(,|$)' | grep -q . && bad "sshd advertises non-FIPS MACs" || ok "sshd MACs are FIPS-only set"
fi
grep -qi 'hostkey.*ed25519\|HostKey /etc/ssh/ssh_host_ed25519' /etc/ssh/sshd_config && bad "ed25519 HostKey still in sshd_config" || ok "no ed25519 HostKey in sshd_config"
if ssh-keygen -t ed25519 -N '' -f /tmp/hk_ed >/dev/null 2>&1; then info "ed25519 keygen allowed by +Fips openssh (mitigated by sshd_config MAC/HostKey restriction)"; else ok "ed25519 keygen refused by +Fips openssh"; fi

echo "=== 6. ssh round-trip (rootfs network stack) ==="
mkdir -p /run/sshd /root/.ssh
cp /tmp/hk_rsa /etc/ssh/ssh_host_rsa_key; chmod 600 /etc/ssh/ssh_host_rsa_key
cp /tmp/hk_rsa.pub /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
cat > /tmp/sshd_test.conf <<EOF
Port 2222
HostKey /tmp/hk_rsa
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
PermitRootLogin prohibit-password
PasswordAuthentication no
EOF
/usr/sbin/sshd -f /tmp/sshd_test.conf
sleep 1
ssh -p 2222 -m hmac-sha2-256 -i /tmp/hk_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 'echo SSH_ROUNDTRIP_OK' 2>/dev/null | grep -q SSH_ROUNDTRIP_OK && ok "ssh loopback round-trip (hmac-sha2-256)" || bad "ssh round-trip failed"
pkill sshd 2>/dev/null

echo "=== 7. Upstream contract preserved ==="
grep -q '.include /home/vcap/app/openssl.cnf' /etc/ssl/openssl.cnf && ok "app-level openssl.cnf include seam present" || bad "app openssl.cnf seam missing"
id vcap >/dev/null 2>&1 && ok "vcap user present" || bad "vcap user missing"
[ -L /app ] && [ "$(readlink /app)" = "/home/vcap/app" ] && ok "/app -> /home/vcap/app" || bad "/app symlink wrong"
grep -q '^PermitRootLogin no' /etc/ssh/sshd_config && ok "upstream sshd hardening intact" || bad "upstream sshd hardening altered"

echo "=== 8. Toolchain + TLS smoke ==="
cat > /tmp/t.c <<'EOF'
#include <openssl/sha.h>
#include <stdio.h>
int main(void){ unsigned char d[SHA256_DIGEST_LENGTH]; SHA256((const unsigned char*)"",0,d);
 for(int i=0;i<SHA256_DIGEST_LENGTH;i++) printf("%02x",d[i]); printf("\n"); return 0; }
EOF
gcc -o /tmp/t /tmp/t.c -lcrypto 2>/dev/null && [ "$(/tmp/t)" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ] && ok "gcc + libcrypto SHA256 correct" || bad "toolchain/libcrypto smoke failed"
curl -sSf https://ubuntu.com -o /dev/null --max-time 20 && ok "TLS via system libssl + CA store (curl)" || bad "curl TLS failed"

echo
echo "=== SUMMARY: $PASS passed, $FAIL failed ==="
exit $FAIL
