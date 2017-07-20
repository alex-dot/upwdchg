## UPwdChg contab

# Clean-up stale password nonces
0 0 * * *  root  test -x /usr/bin/upwdchg-daemon && eval "$(/usr/bin/upwdchg-daemon --showconf 'token.public_directory')" && [ -n "${token_public_directory}" ] && find "${token_public_directory}" -type f -name '*.nonce' -mmin +1440 -delete
