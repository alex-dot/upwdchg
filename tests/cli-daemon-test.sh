#!/bin/bash
# -*- mode:shell-script; tab-width:2; sh-basic-offset:2; intent-tabs-mode:nil; -*-
# ex: filetype=sh tabstop=2 softtabstop=2 shiftwidth=2 expandtab autoindent smartindent


## Environment
[ "$(dirname "$0")" != '.' ] && echo "ERROR: Please run tests from their actual directory" && exit
source ./resources/ENVIRONMENT
mkdir -p ./tmp/plugins.d
trap 'rm -f ./tmp/*.token ./tmp/plugins.d/*' EXIT


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


## Plugins
rm -f ./tmp/plugins.d/*

# ShowTokenInfo
cp -p ../backend/plugins/ShowTokenInfo ./tmp/plugins.d/01-ShowTokenInfo

# CheckTimestamp
cp -p ../backend/plugins/CheckTimestamp ./tmp/plugins.d/02-CheckTimestamp

# CheckPasswordChange
cp -p ../backend/plugins/CheckPasswordChange ./tmp/plugins.d/05-CheckPasswordChange

# CheckUsernamePolicy
cp -p ../backend/plugins/CheckUsernamePolicy ./tmp/plugins.d/06-CheckUsernamePolicy
sed -i "s|^UPWDCHG_PLUGIN_USERNAME_TYPE_\([^=]*\)=.*|UPWDCHG_PLUGIN_USERNAME_TYPE_\1=0|" ./tmp/plugins.d/06-CheckUsernamePolicy

# CheckPasswordPolicy
cp -p ../backend/plugins/CheckPasswordPolicy ./tmp/plugins.d/07-CheckPasswordPolicy
sed -i "s|^UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=.*|UPWDCHG_PLUGIN_PASSWORD_CHARSET_NOTASCII=0|" ./tmp/plugins.d/07-CheckPasswordPolicy


## Daemon

# Daemon ERROR
echo "* TEST(Daemon): Process an invalid 'password-change' token ... "
# ... write an invalid 'password-change' token
rm -f ./tmp/*.token ./tmp/*.nonce ./tmp/plugins.d/stderr
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/backend-private.pem -Ku ./resources/frontend-public.pem \
  ./tmp/password-change.token
# ... launch the processing daemon
../backend/upwdchg-daemon \
  -C ./resources/config.py.ini \
  --foreground \
2> ./tmp/plugins.d/stderr \
& DAEMON_PID=$!
sleep 3
echo "* TEST(Daemon): ... expect daemon is NOT running ... "
ps -p ${DAEMON_PID} >/dev/null 2>&1 && false || true
_testResult
kill ${DAEMON_PID} >/dev/null 2>&1
echo "* TEST(Daemon): ... expect processing INFO ... "
fgrep 'INFO' ./tmp/plugins.d/stderr
_testResult
echo "* TEST(Daemon): ... expect processing ERROR ... "
fgrep 'ERROR' ./tmp/plugins.d/stderr
_testResult

# Daemon OK, processing OK
echo
echo "* TEST(Daemon): Process a valid 'password-change' token ... "
# ... write a 'password-change' token
rm -f ./tmp/*.token ./tmp/*.nonce ./tmp/plugins.d/stderr
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
  ./tmp/password-change.token
# ... launch the processing daemon
../backend/upwdchg-daemon \
  -C ./resources/config.py.ini \
  --foreground \
2> ./tmp/plugins.d/stderr \
& DAEMON_PID=$!
sleep 3
echo "* TEST(Daemon): ... expect daemon is running ... "
ps -p ${DAEMON_PID} >/dev/null 2>&1
_testResult
kill ${DAEMON_PID} >/dev/null 2>&1
echo "* TEST(Daemon): ... expect processing INFO ... "
fgrep 'INFO' ./tmp/plugins.d/stderr
_testResult
echo "* TEST(Daemon): ... expect NO processing ERROR ... "
fgrep 'ERROR' ./tmp/plugins.d/stderr && false || true
_testResult

# Daemon OK, processing ERROR
echo
echo "* TEST(Daemon): Process an expired 'password-change' token ... "
sed -i "s|^UPWDCHG_PLUGIN_TIMESTAMP_TTL=.*|UPWDCHG_PLUGIN_TIMESTAMP_TTL=1|" ./tmp/plugins.d/02-CheckTimestamp
# ... write a 'password-change' token
rm -f ./tmp/*.token ./tmp/*.nonce ./tmp/plugins.d/stderr
../backend/upwdchg-token \
  -W -Wt 'password-change' -Wu 'test-Benützername' -Wp 'test-Paßw0rt_new' -Wo 'test-Paßw0rt_old' -Wn 'test-Paßw0rt_nonce' \
  -Kv ./resources/frontend-private.pem -Ku ./resources/backend-public.pem \
  ./tmp/password-change.token
sleep 2
# ... launch the processing daemon
../backend/upwdchg-daemon \
  -C ./resources/config.py.ini \
  --foreground \
2> ./tmp/plugins.d/stderr \
& DAEMON_PID=$!
sleep 3
echo "* TEST(Daemon): ... expect daemon is running ... "
ps -p ${DAEMON_PID} >/dev/null 2>&1
_testResult
kill ${DAEMON_PID} >/dev/null 2>&1
echo "* TEST(Daemon): ... expect processing INFO ... "
fgrep 'INFO' ./tmp/plugins.d/stderr
_testResult
echo "* TEST(Daemon): ... expect processing ERROR ... "
fgrep 'ERROR' ./tmp/plugins.d/stderr
_testResult


## Done
exit ${TEST_ERRORS}
