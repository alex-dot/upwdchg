# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

#
# Universal Password Changer (UPwdChg)
# Copyright (C) 2014-2018 Cedric Dufour <http://cedric.dufour.name>
# Author: Cedric Dufour <http://cedric.dufour.name>
#
# The Universal Password Changer (UPwdChg) is free software:
# you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, Version 3.
#
# The Universal Password Changer (UPwdChg) is distributed in the hope
# that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU General Public License for more details.
#
# SPDX-License-Identifier: GPL-3.0
# License-Filename: LICENSE/GPL-3.0.txt
#

#------------------------------------------------------------------------------
# DEPENDENCIES
#------------------------------------------------------------------------------

# UPwdChg
from UPwdChg import \
    UPWDCHG_VERSION, \
    UPWDCHG_ENCODING, \
    Config, \
    TokenReader
from UPwdChg.Util import \
    Process

# Extra
# ... deb: python3-daemon, python3-ldap
from daemon import \
    DaemonContext
from daemon.runner import \
    emit_message, \
    is_pidfile_stale, \
    make_pidlockfile
try:
    import ldap
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

# Standard
import argparse as AP
from codecs import \
    open
from email.mime.text import \
    MIMEText
import os
import signal
from subprocess import \
    Popen, \
    PIPE
import stat
import sys
import syslog
from time import \
    gmtime, \
    sleep, \
    strftime


#------------------------------------------------------------------------------
# CONSTANTS
#------------------------------------------------------------------------------

UPWDCHG_DAEMON_CONFIGSPEC = 'upwdchg-daemon.conf.spec'


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class Daemon:
    """
    Universal Password Changer Token Processing Daemon
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        # Fields
        self.__bInterrupted = False
        self._bDebug = False
        self._sFileConfig = None
        self._oConfig = Config()


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def _signal(self, signal, frame):
        self.__bInterrupted = True


    def _sendmail(self, _sFrom, _sTo, _sSubject, _sBody):
        """
        Send the given e-mail message.
        """

        oMIMEText = MIMEText(_sBody, 'plain')
        oMIMEText['From'] = _sFrom
        oMIMEText['Subject'] = _sSubject
        oMIMEText['To'] = _sTo
        oPopen = Popen([self._oConfig['email']['sendmail_binary'], '-t'], stdin=PIPE)
        oPopen.communicate(oMIMEText.as_string().encode(sys.stdin.encoding))


    def config(self, _sFileConfig):
        """
        Load the configuration from the given file; returns a non-zero exit code in case of failure.
        """

        try:
            self._oConfig.load(_sFileConfig)
            self._sFileConfig = _sFileConfig
        except Exception as e:
            sys.stderr.write('ERROR[Daemon]: Failed to load configuration; %s\n' % str(e))
            return 1

        return 0


    def processTokens(self):
        """
        Watch directory for (incoming) tokens and process them; returns a non-zero exit code in case of failure.
        """

        # Configured (?)
        if self._sFileConfig is None:
            sys.stderr.write('ERROR[Daemon]: Unconfigured\n')
            return 1

        # Check tokens directory
        if not os.path.isdir(self._oConfig['backend']['tokens_directory']):
            sys.stderr.write('ERROR[Daemon]: Invalid tokens directory\n')
            return 1
        fDirTokensMTime_1 = 0.0

        # Processing object
        oProcess = Process()
        oProcess.config(self._sFileConfig, self._oConfig['daemon']['plugins_directory'])

        # Loop
        iError = 0
        while True:
            # Check loop conditions
            if self.__bInterrupted:
                break
            if self._oConfig['daemon']['max_errors'] and iError >= self._oConfig['daemon']['max_errors']:
                sys.stderr.write('CRITICAL[Daemon]: Too-many errors (%d); bailing out\n' % iError)
                if self._oConfig['email']['admin_address']:
                    try:
                        self._sendmail(
                            self._oConfig['email']['sender_address'],
                            self._oConfig['email']['admin_address'],
                            self._oConfig['email']['subject_prefix']+'Critical Error',
                            'CRITICAL[Daemon]: Too-many errors (%d); bailing out\n' % iError
                        )
                    except Exception as e:
                        pass
                return 1

            # Check (private/incoming) tokens directory for changes
            try:
                fDirTokensMTime_2 = os.stat(self._oConfig['backend']['tokens_directory']).st_mtime
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens directory last modification time; %s\n' % str(e))
                fDirTokensMTime_2 = fDirTokensMTime_1
            if (fDirTokensMTime_2 - fDirTokensMTime_1) < 0.1:
                if self._bDebug:
                    sys.stderr.write('DEBUG[Daemon]: Sleeping for %f seconds...\n' % self._oConfig['daemon']['process_interval'])
                sleep(self._oConfig['daemon']['process_interval'])
                continue
            if self._bDebug:
                sys.stderr.write('DEBUG[Daemon]: Detected changes in tokens directory\n')

            # List tokens
            lsFilesToken = list()
            try:
                for sFile in os.listdir(self._oConfig['backend']['tokens_directory']):
                    sFile = self._oConfig['backend']['tokens_directory'].rstrip(os.sep)+os.sep+sFile
                    if os.path.isfile(sFile):
                        lsFilesToken.append(sFile)
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens list; %s\n' % str(e))
                continue
            iFilesToken = len(lsFilesToken)
            if not iFilesToken:
                if fDirTokensMTime_1:
                    sys.stderr.write('WARNING[Daemon]: No password change token found\n')
                fDirTokensMTime_1 = fDirTokensMTime_2
                continue
            if self._oConfig['daemon']['max_tokens'] and iFilesToken >= self._oConfig['daemon']['max_tokens']:
                sys.stderr.write('CRITICAL[Daemon]: Too-many tokens (%d); bailing out\n' % iFilesToken)
                if self._oConfig['email']['admin_address']:
                    try:
                        self._sendmail(
                            self._oConfig['email']['sender_address'],
                            self._oConfig['email']['admin_address'],
                            self._oConfig['email']['subject_prefix']+'Critical Error',
                            'CRITICAL[Daemon]: Too-many tokens (%d); bailing out\n' % iFilesToken
                        )
                    except Exception as e:
                        pass
                return 1
            lsFilesToken.sort()

            # Update tokens directory last modification time
            fDirTokensMTime_1 = fDirTokensMTime_2

            # Process tokens
            iErrorTokens = 0
            lTokenAllowedTypes = self._oConfig['daemon']['allowed_types'].replace(' ', '').split(',')
            for sFileToken in lsFilesToken:
                lsOutputs = []
                iErrorToken = 0
                bTokenInvalid = False
                bSkipProcessing = False
                sys.stderr.write('INFO[Daemon]: Processing token; %s\n' % sFileToken)

                # ... token read
                oToken = TokenReader()
                oToken.config(self._oConfig['backend']['private_key_file'], self._oConfig['frontend']['public_key_file'])
                if oToken.readToken(sFileToken):
                    iErrorToken += 1
                    bTokenInvalid = True
                    bSkipProcessing = True
                    sys.stderr.write('ERROR[Daemon]: Failed to read token; %s\n' % sFileToken)
                    lsOutputs.append('ERROR[UPwdChg]: Internal error; please contact your system administrator\n')

                # ... token type
                if not bTokenInvalid:
                    sTokenType = oToken.getType()
                    if not sTokenType in lTokenAllowedTypes:
                        iErrorToken += 1
                        bSkipProcessing = True
                        sys.stderr.write('ERROR[Daemon]: Token type not allowed; %s\n' % sTokenType)
                        lsOutputs.append('ERROR[UPwdChg]: Internal error; please contact your system administrator\n')
                    if self._bDebug:
                        sys.stderr.write('DEBUG[Daemon]: Allowed token type; %s\n' % sTokenType)

                # ... token processing (plugins)
                if not bSkipProcessing:
                    try:
                        (iReturn, lsOutputs) = oProcess.processToken(sFileToken, _sTokenType=sTokenType)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Token processing succeeded (exit=%d)\n' % iReturn)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Token processing failure\n')
                        lsOutputs = list()

                # ... processing output
                if lsOutputs and (self._oConfig['email']['admin_address'] or self._oConfig['email']['user_send']):
                    sOutput = ''.join(lsOutputs)

                    # ... retrieve token username
                    sUsername = oToken['username'] if not bTokenInvalid else '##INVALID_TOKEN##'

                    # ... e-mail body template
                    if self._oConfig['email']['body_template_file']:
                        try:
                            oFile = open(self._oConfig['email']['body_template_file'], 'r', encoding=self._oConfig['email']['encoding'])
                            sOutput = (''.join(oFile.readlines())).replace('%{OUTPUT}', sOutput)
                            oFile.close()
                        except Exception as e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to load e-mail body template; %s\n' % str(e))

                    # ... create e-mail object
                    sSubject = 'Processing Results (%s, %s)' % (sUsername, strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()))

                    # ... send to administrator
                    if self._oConfig['email']['admin_address']:
                        try:
                            self._sendmail(
                                self._oConfig['email']['sender_address'],
                                self._oConfig['email']['admin_address'],
                                self._oConfig['email']['subject_prefix']+sSubject,
                                sOutput
                            )
                            if self._bDebug:
                                sys.stderr.write('DEBUG[Daemon]: Successfully sent token processing output to administrator; %s\n' % self._oConfig['email']['admin_address'])
                        except Exception as e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to administrator; %s\n' % str(e))

                    # ... send to user
                    if not bTokenInvalid and self._oConfig['email']['user_send']:
                        sEmailUser = None

                        if self._oConfig['email']['user_address_from_ldap']:
                            # ... use ldap-stored e-mail address
                            try:

                                # ... initialize connection
                                try:
                                    oLdap = ldap.initialize(self._oConfig['ldap']['uri'])
                                    oLdap.protocol_version = ldap.VERSION3
                                except Exception as e:
                                    raise RuntimeError('failed to initialize connection; %s' % str(e))

                                lLdapAttrList = [self._oConfig['ldap']['email_attribute']]
                                if self._oConfig['ldap']['search_scope'] == 'ldap.SCOPE_BASELEVEL':
                                    iLdapScope = ldap.SCOPE_BASELEVEL
                                elif self._oConfig['ldap']['search_scope'] == 'ldap.SCOPE_ONELEVEL':
                                    iLdapScope = ldap.SCOPE_ONELEVEL
                                elif self._oConfig['ldap']['search_scope'] == 'ldap.SCOPE_SUBTREE':
                                    iLdapScope = ldap.SCOPE_SUBTREE

                                # ... bind credentials
                                if self._oConfig['ldap']['bind_pwd'].startswith('file://'):
                                    sFile = self._oConfig['ldap']['bind_pwd'][7:]
                                    try:
                                        oFile = open(sFile, 'r', encoding=self._oConfig['ldap']['encoding'])
                                        sBindPwd = oFile.readline()
                                        oFile.close()
                                    except Exception as e:
                                        raise RuntimeError('failed to retrieve bind password from file; %s' % str(e))
                                else:
                                    sBindPwd = self._oConfig['ldap']['bind_pwd']

                                # ... bind to server
                                try:
                                    oLdap.bind_s(self._oConfig['ldap']['bind_dn'], sBindPwd, ldap.AUTH_SIMPLE)
                                except Exception as e:
                                    raise RuntimeError('failed to bind to server; %s' % str(e))

                                # ... retrieve user and its mail attribute
                                try:
                                    if not self._oConfig['ldap']['user_dn']:
                                        lLdapResults = oLdap.search_ext_s(
                                            self._oConfig['ldap']['search_dn'],
                                            iLdapScope,
                                            self._oConfig['ldap']['search_filter'].replace('%{USERNAME}', sUsername),
                                            lLdapAttrList,
                                            sizelimit=2
                                            )
                                    else:
                                        lLdapResults = oLdap.search_ext_s(
                                            self._oConfig['ldap']['user_dn'].replace('%{USERNAME}', sUsername),
                                            ldap.SCOPE_BASE,
                                            '(objectClass=*)',
                                            lLdapAttrList,
                                            sizelimit=2
                                            )
                                    if not lLdapResults:
                                        raise RuntimeError('user not found: %s' % sUsername)
                                    elif len(lLdapResults) > 1:
                                        raise RuntimeError('too many match: %s' % sUsername)
                                    (sUserDn, dAttrs) = lLdapResults[0]
                                    sEmailUser = dAttrs[self._oConfig['ldap']['email_attribute']][0].decode(self._oConfig['ldap']['encoding'])
                                except Exception as e:
                                    raise RuntimeError('failed to retrieve user mail attribute; %s' % str(e))

                                # ... unbind
                                try:
                                    oLdap.unbind_s()
                                except Exception as e:
                                    iErrorToken += 1
                                    sys.stderr.write('ERROR[Daemon]: Failed to unbind from LDAP server; %s\n' % str(e))

                            except Exception as e:
                                iErrorToken += 1
                                sys.stderr.write('ERROR[Daemon]: Failed to retrieve user e-mail address from LDAP server; %s\n' % str(e))

                        else:
                            # ... use user name as e-mail address
                            sEmailUser = sUsername
                            if self._oConfig['email']['user_domain']:
                                sEmailUser += '@'+self._oConfig['email']['user_domain']

                        # ... send the mail
                        if sEmailUser is not None:
                            try:
                                self._sendmail(
                                    self._oConfig['email']['sender_address'],
                                    sEmailUser,
                                    self._oConfig['email']['subject_prefix']+sSubject,
                                    sOutput
                                )
                                if self._bDebug:
                                    sys.stderr.write('DEBUG[Daemon]: Successfully sent token processing output to user; %s\n' % sEmailUser)
                            except Exception as e:
                                iErrorToken += 1
                                sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to user; %s\n' % str(e))

                # ... move token to archive directory (or delete it)
                sFileToken_archive = None
                if self._oConfig['backend']['archive_directory'] is not None:
                    sFileToken_archive = self._oConfig['backend']['archive_directory'].rstrip(os.sep)+os.sep+os.path.basename(sFileToken)
                if sFileToken_archive is not None:
                    try:
                        shutil.move(sFileToken, sFileToken_archive)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Successfully moved token to archive directory; %s\n' % sFileToken_archive)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Failed to move token to archive directory; %s\n' % str(e))
                        sFileToken_archive = None
                if sFileToken_archive is None:
                    try:
                        os.remove(sFileToken)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Successfully deleted token file; %s\n' % sFileToken)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Failed to delete token file; %s\n' % str(e))

                # ... done (processing token)
                if iErrorToken:
                    iErrorTokens += 1

            # Done (processing tokens)
            if iErrorTokens:
                iError += 1
            elif iError:
                iError -= 1

            # Update incoming tokens directory last modification time (after tokens removal)
            try:
                fDirTokensMTime_1 = os.stat(self._oConfig['backend']['tokens_directory']).st_mtime
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens directory last modification time; %s\n' % str(e))
                fDirTokensMTime_1 = fDirTokensMTime_2

        # Done
        return 0


class DaemonLogger:
    """
    Universal Password Changer Token Processing Daemon Logger
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self, _fnLog):
        # Fields
        self.__fnLog = _fnLog
        self.__sBuffer = ''


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def flush(self):
        if self.__sBuffer:
            self.__fnLog(self.__sBuffer)
            self.__sBuffer = ''

    def write(self, _s):
        while _s:
            i = _s.find('\n')
            if i < 0:
                self.__sBuffer += _s
                break
            self.__sBuffer += _s[:i]
            if self.__sBuffer:
                self.__fnLog(self.__sBuffer)
                self.__sBuffer = ''
            _s = _s[i+1:]


    def writelines(self, _lsLines):
        for sLine in _lsLines:
            self.write(sLine)


class DaemonMain(Daemon):
    """
    Universal Password Changer Token Processing Daemon Main Executable
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        Daemon.__init__(self)

        # Fields
        self.__oArgumentParser = None
        self.__oArguments = None

        # Initialization
        self.__initArgumentParser()


    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator)
        """

        # Create argument parser
        self.__oArgumentParser = AP.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # ... configuration file
        self.__oArgumentParser.add_argument(
            '-C', '--config', type=str,
            metavar='<conf-file>',
            default='/etc/upwdchg/backend/upwdchg.conf',
            help='Path to configuration file (default:/etc/upwdchg/backend/upwdchg.conf)')

        # ... PID file
        self.__oArgumentParser.add_argument(
            '-p', '--pid', type=str,
            metavar='<pid-file>',
            default='/var/run/upwdchg-daemon.pid',
            help='Path to daemon PID file (default:/var/run/upwdchg-daemon.pid)')

        # ... remain in foreground
        self.__oArgumentParser.add_argument(
            '-f', '--foreground', action='store_true',
            default=False,
            help='Do not fork to background / Remain on foreground')

        # ... debug
        self.__oArgumentParser.add_argument(
            '-d', '--debug', action='store_true',
            default=False,
            help='Enable debugging messages')

        # ... show configuration
        self.__oArgumentParser.add_argument(
            '--showconf', type=str,
            metavar='<configobj.path>',
            default=None,
            help='Show configuration and exit')

        # ... version
        self.__oArgumentParser.add_argument(
            '-v', '--version', action='version',
            version=('UPwdChg - %s - Cedric Dufour <http://cedric.dufour.name>\n' % UPWDCHG_VERSION))


    def __initArguments(self, _aArguments = None):
        """
        Parses the command-line arguments; returns a non-zero exit code in case of failure.
        """

        # Parse arguments
        if _aArguments is None: _aArguments = sys.argv
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception as e:
            self.__oArguments = None
            sys.stderr.write('ERROR[DaemonMain]: Failed to parse arguments; %s\n' % str(e))
            return 1

        return 0


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def __syslog(self, _sMessage):
        iLevel = syslog.LOG_INFO
        if _sMessage.find('ERROR') >= 0:
            iLevel = syslog.LOG_ERR
        elif _sMessage.find('WARNING') >= 0:
            iLevel = syslog.LOG_WARNING
        elif _sMessage.find('DEBUG') >= 0:
            iLevel = syslog.LOG_DEBUG
        syslog.syslog(iLevel, _sMessage)


    def __daemon(self):
        """
        Daemonizes the process; returns a non-zero exit code in case of failure.
        """

        # Daemonize
        try:
            # Create and check PID file
            oPidLockFile = make_pidlockfile(self.__oArguments.pid, 0)
            if is_pidfile_stale(oPidLockFile):
                oPidLockFile.break_lock()
            if oPidLockFile.is_locked():
                sys.stderr.write('ERROR[DaemonMain]: Daemon process already running; PID=%s\n' % oPidLockFile.read_pid())
                return 1

            # Create daemon context
            oDaemonContext = DaemonContext(pidfile=oPidLockFile)
            oDaemonContext.signal_map = { signal.SIGTERM: self._signal }
            oDaemonContext.open()
            emit_message('[%s]' % os.getpid())

            # Redirect standard error to syslog
            syslog.openlog('upwdchg-daemon', syslog.LOG_PID, syslog.LOG_DAEMON)
            sys.stderr = DaemonLogger(self.__syslog)

            # Execute
            return self.processTokens()
        except Exception as e:
            sys.stderr.write('ERROR[DaemonMain]: Failed to fork to background; %s\n' % str(e))
            return 1


    def execute(self):
        """
        Executes; returns a non-zero exit code in case of failure.
        """

        # Initialize

        # ... arguments
        iReturn = self.__initArguments()
        if iReturn:
            return iReturn

        # ... configuration
        self._bDebug = self.__oArguments.debug
        iReturn = self.config(self.__oArguments.config)
        if iReturn: return iReturn

        # Show configuration (?)
        if self.__oArguments.showconf is not None:
            sys.stdout.write(self._oConfig.toString(self.__oArguments.showconf))
            return 0

        # Check dependencies
        if self._oConfig['email']['user_send'] and self._oConfig['email']['user_address_from_ldap'] and not LDAP_AVAILABLE:
            sys.stderr.write('ERROR[DaemonMain]: Missing LDAP dependency\n')
            return 1

        # Fork to background (?)
        if not self.__oArguments.foreground:
            return self.__daemon()

        # Foreground processing
        signal.signal(signal.SIGINT, self._signal)
        signal.signal(signal.SIGTERM, self._signal)
        return self.processTokens()

        # Done
        return 0
