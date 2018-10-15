#!/bin/bash
# -*- mode:shell-script; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*-
# ex: filetype=sh tabstop=2 softtabstop=2 shiftwidth=2 expandtab autoindent smartindent


## Environment
[ "$(dirname "$0")" != '.' ] && echo "ERROR: Please run tests from their actual directory" && exit
source ./resources/ENVIRONMENT


## Helpers
TEST_ERRORS=0
function _testResult {
  if [ $? -eq 0 ]; then
    echo '* OK'
  else
    echo '* FAIL'
    let TEST_ERRORS+=1
  fi
}


## Frontend-to-backend tokens

# Write/read a 'password-nonce-request' token
echo -n "* TEST(CLI): Write/read a 'password-nonce-request' token ... "
../backend/upwdchg-token \
  -W -Wt 'password-nonce-request' -Wu 'test-Benützername' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
| ../backend/upwdchg-token -R -Rp \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
> /dev/null
_testResult


# Write/read a 'password-change' token
echo -n "* TEST(CLI): Write/read a 'password-change' token ... "
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
| ../backend/upwdchg-token -R -Rp \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
> /dev/null
_testResult


# Write/read a 'password-reset' token
echo -n "* TEST(CLI): Write/read a 'password-reset' token ... "
../backend/upwdchg-token \
  -W -Wt 'password-reset' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
| ../backend/upwdchg-token -R -Rp \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
> /dev/null
_testResult


## Backend-to-frontend tokens

# Write/read a 'password-nonce' token
echo -n "* TEST(CLI): Write/read a 'password-nonce' token ... "
../backend/upwdchg-token \
  -W -Wt 'password-nonce' -Wu 'test-Benützername' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
| ../backend/upwdchg-token -R -Rp \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
> /dev/null
_testResult


## Done
exit ${TEST_ERRORS}

