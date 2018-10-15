## UPwdChg crontab

# Clean-up stale password nonces
0 0 * * *  root  test -x /usr/bin/upwdchg-daemon && eval "$(/usr/bin/upwdchg-daemon --showconf 'frontend.tokens_directory')" && [ -n "${frontend_tokens_directory}" ] && find "${frontend_tokens_directory}" -type f -name '*.nonce' -mmin +1440 -delete

