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

# Sender with OpenPGP and S/MIME key
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" sender-mixed@example.net default default never

# Sender with OpenPGP key only
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" sender-openpgp@example.net default default never

# Recipient with full validity
gpg --quick-gen-key --batch --pinentry-mode loopback --passphrase "" --no-auto-trust-new-key "prefer-openpgp@example.net" default default never
gpg --delete-secret-keys --batch --yes $(gpg -K --batch --with-colons prefer-openpgp@example.net | grep fpr | head -1 | cut -d ':' -f 10)
gpg --quick-sign-key --default-key $(gpg -K --batch --with-colons ca-full@example.net | grep fpr | head -1 | cut -d ':' -f 10) --batch --pinentry-mode loopback --passphrase "" $(gpg -k --batch --with-colons prefer-openpgp@example.net | grep fpr | head -1 | cut -d ':' -f 10)

# Recipient with marginal validity
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

```
gpgsm --gen-key --batch --pinentry-mode loopback --passphrase "" <<eof | gpgsm --import
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Serial: random
Name-DN: CN=Sender Mixed,O=example,C=DE
Name-Email: sender-mixed@example.net
eof
gpgsm -k sender-mixed@example.net | grep 'sha1 fpr' | sed 's/\s*sha1 fpr:\s*\([0-9A-F].*\)/\1 S relax/' >>trustlist.txt

gpgsm --gen-key --batch --pinentry-mode loopback --passphrase "" <<eof | gpgsm --import
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Serial: random
Name-DN: CN=Sender S/MIME,O=example,C=DE
Name-Email: sender-smime@example.net
eof
gpgsm -k sender-smime@example.net | grep 'sha1 fpr' | sed 's/\s*sha1 fpr:\s*\([0-9A-F].*\)/\1 S relax/' >>trustlist.txt

gpgsm --gen-key --batch --pinentry-mode loopback --passphrase "" <<eof | gpgsm --import
dummy
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign, encrypt
Serial: random
Name-DN: CN=Trusted S/MIME,O=example,C=DE
Name-Email: prefer-smime@example.net
eof
gpgsm -k prefer-smime@example.net | grep 'sha1 fpr' | sed 's/\s*sha1 fpr:\s*\([0-9A-F].*\)/\1 S relax/' >>trustlist.txt
```
