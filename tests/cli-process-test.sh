#!/bin/bash
# -*- mode:shell-script; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*-
# ex: filetype=sh tabstop=2 softtabstop=2 shiftwidth=2 expandtab autoindent smartindent


## Environment
[ "$(dirname "$0")" != '.' ] && echo "ERROR: Please run tests from their actual directory" && exit
source ./resources/ENVIRONMENT
mkdir -p ./tmp/plugins.d
trap 'rm -f ./tmp/*.token ./tmp/*.nonce ./tmp/plugins.d/*' EXIT


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


## Resources

# Write a 'password-nonce' token
echo -n "* TEST(Process): Write a 'password-nonce' token ... "
rm -f ./tmp/password-nonce.token
../backend/upwdchg-token \
  -W -Wt 'password-nonce' -Wu 'test-Benützername' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
  ./tmp/test.nonce
_testResult

# Write a 'password-change' token
echo -n "* TEST(Process): Write a 'password-change' token ... "
rm -f ./tmp/password-change.token
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
  ./tmp/password-change.token
_testResult


## Plugins
rm -f ./tmp/plugins.d/*

# ShowTokenInfo
cp -p ../backend/plugins/ShowTokenInfo ./tmp/plugins.d/01-ShowTokenInfo

# CheckTimestamp
cp -p ../backend/plugins/CheckTimestamp ./tmp/plugins.d/02-CheckTimestamp

# CheckPasswordNonce
cp -p ../backend/plugins/CheckPasswordNonce ./tmp/plugins.d/03-CheckPasswordNonce
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR=.*|UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR='./tmp'|" ./tmp/plugins.d/03-CheckPasswordNonce

# NukePasswordNonce
cp -p ../backend/plugins/NukePasswordNonce ./tmp/plugins.d/04-NukePasswordNonce
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR=.*|UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR='./tmp'|" ./tmp/plugins.d/04-NukePasswordNonce

# CheckPasswordChange
cp -p ../backend/plugins/CheckPasswordChange ./tmp/plugins.d/05-CheckPasswordChange

# CheckUsernamePolicy
cp -p ../backend/plugins/CheckUsernamePolicy ./tmp/plugins.d/06-CheckUsernamePolicy
sed -i "s|^UPWDCHG_PLUGIN_USERNAME_TYPE_\([^=]*\)=.*|UPWDCHG_PLUGIN_USERNAME_TYPE_\1=0|" ./tmp/plugins.d/06-CheckUsernamePolicy

# CheckPasswordPolicy
cp -p ../backend/plugins/CheckPasswordPolicy ./tmp/plugins.d/07-CheckPasswordPolicy
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=.*|UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=0|" ./tmp/plugins.d/07-CheckPasswordPolicy


## Process

# Process OK
echo
echo "* TEST(Process): Process a 'password-change' token (expect OK) ... "
../backend/upwdchg-process \
  -C ./resources/config.py.ini \
  -Dp ./tmp/plugins.d \
  ./tmp/password-change.token
_testResult

# Process FAIL
echo
echo "* TEST(Process): Process a 'password-change' token (expect ERROR) ... "
sleep 2
sed -i "s|^UPWDCHG_PLUGIN_TIMESTAMP_TTL=.*|UPWDCHG_PLUGIN_TIMESTAMP_TTL=1|" ./tmp/plugins.d/02-CheckTimestamp
../backend/upwdchg-process \
  -C ./resources/config.py.ini \
  -Dp ./tmp/plugins.d \
  ./tmp/password-change.token \
&& false || true
_testResult


## Done
exit ${TEST_ERRORS}
