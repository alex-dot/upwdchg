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
echo -n "* TEST(Plugins): Write a 'password-nonce' token ... "
rm -f ./tmp/password-nonce.token
../backend/upwdchg-token \
  -W -Wt 'password-nonce' -Wu 'test-Benützername' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
> ./tmp/test.nonce
_testResult

# Write a 'password-change' token
echo -n "* TEST(Plugins): Write a 'password-change' token ... "
rm -f ./tmp/password-change.token
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
> ./tmp/password-change.token
_testResult


## Plugins (individually)

# ShowTokenInfo
cp -p ../backend/plugins/ShowTokenInfo ./tmp/plugins.d/01-ShowTokenInfo
./tmp/plugins.d/01-ShowTokenInfo ./resources/config.py.ini ./tmp/password-change.token

# CheckTimestamp
echo
echo "* TEST(Plugins): CheckTimestamp (expect OK) ... "
cp -p ../backend/plugins/CheckTimestamp ./tmp/plugins.d/02-CheckTimestamp
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/02-CheckTimestamp
./tmp/plugins.d/02-CheckTimestamp ./resources/config.py.ini ./tmp/password-change.token
_testResult
echo "* TEST(Plugins): CheckTimestamp (expect ERROR) ... "
sed -i "s|^UPWDCHG_PLUGIN_TIMESTAMP_TTL=.*|UPWDCHG_PLUGIN_TIMESTAMP_TTL=1|" ./tmp/plugins.d/02-CheckTimestamp
sleep 2
./tmp/plugins.d/02-CheckTimestamp ./resources/config.py.ini ./tmp/password-change.token && false || true
_testResult

# CheckPasswordNonce
echo
echo "* TEST(Plugins): CheckPasswordNonce (expect ERROR) ... "
cp -p ../backend/plugins/CheckPasswordNonce ./tmp/plugins.d/03-CheckPasswordNonce
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/03-CheckPasswordNonce
./tmp/plugins.d/03-CheckPasswordNonce ./resources/config.py.ini ./tmp/password-change.token && false || true
_testResult
echo "* TEST(Plugins): CheckPasswordNonce (expect OK) ... "
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR=.*|UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR='./tmp'|" ./tmp/plugins.d/03-CheckPasswordNonce
./tmp/plugins.d/03-CheckPasswordNonce ./resources/config.py.ini ./tmp/password-change.token
_testResult

# NukePasswordNonce
echo
echo "* TEST(Plugins): NukePasswordNonce (expect ERROR) ... "
cp -p ../backend/plugins/NukePasswordNonce ./tmp/plugins.d/04-NukePasswordNonce
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/04-NukePasswordNonce
./tmp/plugins.d/04-NukePasswordNonce ./resources/config.py.ini ./tmp/password-change.token && false || true
_testResult
echo "* TEST(Plugins): NukePasswordNonce (expect OK) ... "
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR=.*|UPWDCHG_PLUGIN_PASSWORD_NONCE_DIR='./tmp'|" ./tmp/plugins.d/04-NukePasswordNonce
./tmp/plugins.d/04-NukePasswordNonce ./resources/config.py.ini ./tmp/password-change.token
_testResult

# CheckPasswordChange
echo
echo "* TEST(Plugins): CheckPasswordChange (expect OK) ... "
cp -p ../backend/plugins/CheckPasswordChange ./tmp/plugins.d/05-CheckPasswordChange
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/05-CheckPasswordChange
./tmp/plugins.d/05-CheckPasswordChange ./resources/config.py.ini ./tmp/password-change.token
_testResult

# CheckUsernamePolicy
echo
echo "* TEST(Plugins): CheckUsernamePolicy (expect ERROR) ... "
cp -p ../backend/plugins/CheckUsernamePolicy ./tmp/plugins.d/06-CheckUsernamePolicy
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/06-CheckUsernamePolicy
./tmp/plugins.d/06-CheckUsernamePolicy ./resources/config.py.ini ./tmp/password-change.token && false || true
_testResult
echo "* TEST(Plugins): CheckUsernamePolicy (expect OK) ... "
cp -p ../backend/plugins/CheckUsernamePolicy ./tmp/plugins.d/06-CheckUsernamePolicy
sed -i "s|^UPWDCHG_PLUGIN_USERNAME_TYPE_\([^=]*\)=.*|UPWDCHG_PLUGIN_USERNAME_TYPE_\1=0|" ./tmp/plugins.d/06-CheckUsernamePolicy
./tmp/plugins.d/06-CheckUsernamePolicy ./resources/config.py.ini ./tmp/password-change.token
_testResult

# CheckPasswordPolicy
echo
echo "* TEST(Plugins): CheckPasswordPolicy (expect ERROR) ... "
cp -p ../backend/plugins/CheckPasswordPolicy ./tmp/plugins.d/07-CheckPasswordPolicy
sed -i "s|^UPWDCHG_PLUGIN_DEBUG=.*|UPWDCHG_PLUGIN_DEBUG=TokenPlugin.DEBUG_NOTICE|" ./tmp/plugins.d/07-CheckPasswordPolicy
./tmp/plugins.d/07-CheckPasswordPolicy ./resources/config.py.ini ./tmp/password-change.token && false || true
_testResult
echo "* TEST(Plugins): CheckPasswordPolicy (expect OK) ... "
cp -p ../backend/plugins/CheckPasswordPolicy ./tmp/plugins.d/07-CheckPasswordPolicy
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=.*|UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=0|" ./tmp/plugins.d/07-CheckPasswordPolicy
./tmp/plugins.d/07-CheckPasswordPolicy ./resources/config.py.ini ./tmp/password-change.token
_testResult


## Done
exit ${TEST_ERRORS}
