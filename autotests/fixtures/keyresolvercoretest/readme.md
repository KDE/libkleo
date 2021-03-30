# Fixture for KeyResolverTest

## Setup

Set the `GNUPGHOME` environment variable to this folder:
```
export GNUPGHOME=$(pwd)
```

## Generate OpenPGP test keys

Note: gpg 2.3 is needed for the --no-auto-trust-new-key option.

```
# Create an ultimately trusted CA key
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Ultimately trusted CA <ca-ultimate@example.net>" default default never

# Create a fully trusted CA key
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Fully trusted CA <ca-full@example.net>" default default never
gpg --edit-key --command-fd 0 ca-full@example.net <<eof
trust
4
save
eof
gpg --quick-sign-key --default-key $(gpg -K --batch --with-colons ca-ultimate@example.net | grep fpr | head -1 | cut -d ':' -f 10) --batch --pinentry-mode loopback --passphrase "" $(gpg -k --batch --with-colons ca-full@example.net | grep fpr | head -1 | cut -d ':' -f 10)

# Create a marginally trusted CA key
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Marginally trusted CA <ca-marginal@example.net>" default default never
gpg --edit-key --command-fd 0 ca-marginal@example.net <<eof
trust
3
save
eof
gpg --quick-sign-key --default-key $(gpg -K --batch --with-colons ca-ultimate@example.net | grep fpr | head -1 | cut -d ':' -f 10) --batch --pinentry-mode loopback --passphrase "" $(gpg -k --batch --with-colons ca-marginal@example.net | grep fpr | head -1 | cut -d ':' -f 10)

# Sender with OpenPGP and S/MIME certificate
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" sender-mixed@example.net default default never

# Sender with OpenPGP key only
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" sender-openpgp@example.net default default never

# Recipient with ultimate validity (higher than corresponding S/MIME certificate)
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "prefer-openpgp@example.net" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons prefer-openpgp@example.net | grep fpr | head -1 | cut -d ':' -f 10)

# Recipient with full validity (same as corresponding S/MIME certificate)
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" --no-auto-trust-new-key "full-validity@example.net" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons full-validity@example.net | grep fpr | head -1 | cut -d ':' -f 10)
gpg --quick-sign-key --default-key $(gpg -K --batch --with-colons ca-full@example.net | grep fpr | head -1 | cut -d ':' -f 10) --batch --pinentry-mode loopback --passphrase "" $(gpg -k --batch --with-colons full-validity@example.net | grep fpr | head -1 | cut -d ':' -f 10)

# Recipient with marginal validity (lower than corresponding S/MIME certificate)
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" --no-auto-trust-new-key "prefer-smime@example.net" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons prefer-smime@example.net | grep fpr | head -1 | cut -d ':' -f 10)
gpg --quick-sign-key --default-key $(gpg -K --batch --with-colons ca-marginal@example.net | grep fpr | head -1 | cut -d ':' -f 10) --batch --pinentry-mode loopback --passphrase "" $(gpg -k --batch --with-colons prefer-smime@example.net | grep fpr | head -1 | cut -d ':' -f 10)
```

### Unused OpenPGP keys
```
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Untrusted OpenPGP 1 <untrusted-openpgp@example.net>" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons "Untrusted OpenPGP 1 <untrusted-openpgp@example.net>" | grep fpr | head -1 | cut -d ':' -f 10)
gpg --edit-key --command-fd 0 "Untrusted OpenPGP 1 <untrusted-openpgp@example.net>" <<eof
trust
1
save
eof

gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Untrusted OpenPGP 2 <untrusted-openpgp@example.net>" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons "Untrusted OpenPGP 2 <untrusted-openpgp@example.net>" | grep fpr | head -1 | cut -d ':' -f 10)
gpg --edit-key --command-fd 0 "Untrusted OpenPGP 2 <untrusted-openpgp@example.net>" <<eof
trust
1
save
eof

gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Untrusted Mixed OpenPGP <untrusted-mixed@example.net>" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons untrusted-mixed@example.net | grep fpr | head -1 | cut -d ':' -f 10)
gpg --edit-key --command-fd 0 untrusted-mixed@example.net <<eof
trust
1
save
eof

gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" "Expired <expired@example.net>" default default seconds=1
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons expired@example.net | grep fpr | head -1 | cut -d ':' -f 10)
```

## Generate S/MIME test keys

### Generate a Test CA certificate and mark it as trusted

```
mkdir -p demoCA/newcerts
touch demoCA/index.txt
echo test | openssl req -x509 \
    --passout stdin \
    -subj "/CN=Test CA/O=example/C=DE" \
    --addext "keyUsage = critical, Certificate Sign, CRL Sign" \
    -days 36524 \
    -newkey rsa:2048 \
    -keyout test-ca.key.pem \
    -out test-ca.cert.pem
gpgsm --import test-ca.cert.pem
gpgsm -k "Test CA" | grep 'sha1 fpr' | sed 's/\s*sha1 fpr:\s*\([0-9A-F].*\)/\1 S relax/' >>trustlist.txt
```

### Generate some test keys certified by the Test CA

```
# Sender with OpenPGP and S/MIME certificate
gpgsm --gen-key --armor --batch --pinentry-mode loopback --passphrase "" <<eof >sender-mixed.req.pem
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Name-DN: CN=Sender Mixed,O=example,C=DE
Name-Email: sender-mixed@example.net
eof
echo test | openssl ca -config ./openssl.cnf -batch --passin stdin -keyfile test-ca.key.pem -in sender-mixed.req.pem -out sender-mixed.cert.pem
gpgsm --import sender-mixed.cert.pem

# Sender with S/MIME certificate only
gpgsm --gen-key --armor --batch --pinentry-mode loopback --passphrase "" <<eof >sender-smime.req.pem
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Name-DN: CN=Sender S/MIME,O=example,C=DE
Name-Email: sender-smime@example.net
eof
echo test | openssl ca -config ./openssl.cnf -batch --passin stdin -keyfile test-ca.key.pem -in sender-smime.req.pem -out sender-smime.cert.pem
gpgsm --import sender-smime.cert.pem

# Recipient with full validity (higher than corresponding OpenPGP key)
gpgsm --gen-key --armor --batch --pinentry-mode loopback --passphrase "" <<eof >prefer-smime.req.pem
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Name-DN: CN=Trusted S/MIME,O=example,C=DE
Name-Email: prefer-smime@example.net
eof
echo test | openssl ca -config ./openssl.cnf -batch --passin stdin -keyfile test-ca.key.pem -in prefer-smime.req.pem -out prefer-smime.cert.pem
gpgsm --import prefer-smime.cert.pem

# Recipient with full validity (same as corresponding S/MIME certificate)
gpgsm --gen-key --armor --batch --pinentry-mode loopback --passphrase "" <<eof >full-validity.req.pem
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Name-DN: CN=S/MIME w/ same validity as OpenPGP,O=example,C=DE
Name-Email: full-validity@example.net
eof
echo test | openssl ca -config ./openssl.cnf -batch --passin stdin -keyfile test-ca.key.pem -in full-validity.req.pem -out full-validity.cert.pem
gpgsm --import full-validity.cert.pem

# Recipient with full validity (lower than corresponding OpenPGP key)
gpgsm --gen-key --armor --batch --pinentry-mode loopback --passphrase "" <<eof >prefer-openpgp.req.pem
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Name-DN: CN=S/MIME w/ lower validity than OpenPGP,O=example,C=DE
Name-Email: prefer-openpgp@example.net
eof
echo test | openssl ca -config ./openssl.cnf -batch --passin stdin -keyfile test-ca.key.pem -in prefer-openpgp.req.pem -out prefer-openpgp.cert.pem
gpgsm --import prefer-openpgp.cert.pem
```
