#!/bin/bash --
################################################################################
#                                                                              #
# slackware security patcher                                                   #
# pyllyukko <at> maimed <dot> org                                              #
# http://maimed.org/~pyllyukko/                                                #
#                                                                              #
# modified:	2012 Jul 16
#                                                                              #
# (at least) the following packages are needed to run this:                    #
#   - gnupg                                                                    #
#   - wget                                                                     #
#   - pkgtools (obviously!)                                                    #
#   - gawk                                                                     #
#   - sed                                                                      #
#                                                                              #
#  tested with (at least) the following slackware versions:                    #
#    - 13.37                                                                   #
#    - 13.1                                                                    #
#    - 12.2                                                                    #
#                                                                              #
# ############################################################################ #
#                                                                              #
# this is roughly how this script works:
#                                                                              #
#   - perform a bunch of sanity checks
#   - detect the Slackware version and architecture in use
#   - fetch the patches/FILE_LIST		file from $MAIN_MIRROR FTP
#   - fetch the patches/CHECKSUMS.md5		file from $MAIN_MIRROR FTP
#   - fetch the patches/CHECKSUMS.md5.asc	file from $MAIN_MIRROR FTP
#   - verify the PGP signature of CHECKSUMS.md5
#   - verify the FILE_LIST MD5 from CHECKSUMS.md5
#   - at this point we should be confident that the patch list is authentic
#   - read all available packages from FILE_LIST into $PACKAGES[] array

#   - go through the $PACKAGES[] array:
#     - check if the package in question is installed on the local system
#     - if $SELECT_UPDATES_INDIVIDUALLY is 1, let user choose whether to add
#       the package to the $UPDATES[] array
#     - go through the $UPDATE_BLACKLIST[] array to see if we should skip this
#       patch
#     - verify the slackware version tag in the package's revision field is
#       correct, if available at all that is
#     - if SKIP_VERSION_TEST is 0, perform version comparison against the
#       currently installed versions with version_checker() and
#       do_version_check() functions
#       - if versions are the same, compare the revisions
#     - if SKIP_VERSION_TEST is 1, just compare whether the versions are
#       exactly same
#   - add suitable packages to the $UPDATES[] array
#   - print a brief summary about the packages in the $UPDATES[] array

#   - start processing the $UPDATES[] array:
#     - try to fetch the SSA ID for the patch from www.slackware.com
#     - check if the patch is a kernel upgrade, so we can notify the user that
#       it needs some manual work
#     - try all the $MIRRORS[] until the package and it's PGP signature file
#       are downloaded
#     - verify the package's MD5 from CHECKSUMS.md5 (note that CHECKSUMS.md5
#       itself should already be verified at this point, also see
#       $CHECKSUMS_VERIFIED variable)
#     - verify the package's PGP signature
#     - run upgradepkg with --dry-run first and the the real deal
#     - if everything went well, add the applied patch to $UPGRADED_PACKAGES[]
#       array, otherwise to the $FAILED_PACKAGES[] array
#                                                                              #
#   ... to be continued
#                                                                              #
# ############################################################################ #
#                                                                              #
# NOTES:                                                                       #
#                                                                              #
# TODO: (- = pending & * = done)                                               #
#   * FTP_PATH_SUFFIX, e.g. extra/                                             #
#   - compare_md5(), fetch_mirror_loop(), time_convert()                       #
#   - message > COLUMNS checks                                                 #
#   - upgrade certain packages (linux-[faqs|howtos], e.g.) from current        #
#   - regexp_friendly()                                                        #
#   - MORE COMMENTS!!!                                                         #
#   - syslog                                                                   #
#   - mirror option switch!                                                    #
#   * static error/exit/return codes: ok, failed, error, fatal error           #
#   - scan extra/ in changelog!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
#   - MIRRORS_fi[] etc.                                                        #
#   - $SKIP_CHECKS, revision check at least                                    #
#     - force switch? -- ignore gpg's and stuff?!?                             #
#   - 20.3.2008: minimize dependencies                                         #
#   - 21.3.2008: optimize or rewrite version checking functions!!!             #
#   - 18.4.2008: search in other directories than patches too!                 #
#   - 9.8.2009: do a sanity check function which verifies that all the patches #
#               get processed (regexps are ok and such)                        #
#   - 22.8.2009: add user agent                                                #
#   - 19.9.2009: ULTIMATE GOAL: cron                                           #
#   * 19.9.2009: "standard" output mode, eg. wget prints what it normally does #
#     - could be fd5?
#     - programs:
#       - wget
#       - gpgv
#       - upgradepkg
#       - others?
#     - coproc that logs from fd5?
#   - 19.9.2009: gettext support???                                            #
#   * 19.9.2009: somehow print the SSA id, maybe even cve...                   #
#     - from osvdb?
#    4.10.2009   -- trap DEBUG?                                                #
#    8.10.2009   -- we could add a comparison count on read packages (grep -c) #
#   - 22.7.2010: revamp the whole message system, maybe a function instead of  #
#                all the 1>&3 and ${HL} stuff?                                 #
#   * 18.8.2010: verify md5 of FILE_LIST                                       #
#   * 24.10.2010: replace the booleans                                         #
#                 * run check update before the actual update                  #
#   - 12.3.2011: add a function to get and import the PGP key                  #
#   - 23.4.2011: option switch that skips the version comparisons
#   - 25.4.2011: break the script down with functions, so the main function
#                and loops look cleaner
#     - constructing PACKAGES[] from security_update() to it's own function    #
#   - 9.11.2011: restart certain services after upgrade?
#   - 8.1.2012: wild idea: in case of updated libraries, could we check which
#     programs might have the old version loaded in memory with something like
#     lsof?
#   - 8.1.2012: something like
#     http://connie.slackware.com/~alien/tools/rsync_slackware_patches.sh ?
#   - 17.1.2012: compare timestamp / lastmod of FILE_LIST with FTP ? to verify the file is really the latest
#   - 2.3.2012: downgrade?
#   - 1.5.2012: replace some of the echo's with printf's to make it more
#               readable (too much variables)
#                                                                              #
# changelog:                                                                   #
#    ?. ?.????   -- initial version=)                                          #
#    8. 8.2006   -- cleanups, added blacklist                                  #
#   10. 8.2006   -- fixes                                                      #
#   29. 8.2006   -- more fixes                                                 #
#   15. 9.2006   -- removed the disk space checks                              #
#   27. 3.2007   -- this script breaks with bash-3.2.015 (patch for 11.0),     #
#                   added bash to the blacklist temporarily                    #
#   28. 3.2007   -- added a notice when newer package exists locally,          #
#                   removed seamonkey from blacklist -> install mozilla-nss    #
#                   from patches and gaim starts working again!                #
#   30. 5.2007   -- reworked everything related to gpg -> cleaned up           #
#    8. 7.2007   -- added    '-H' switch                                       #
#   19. 7.2007   -- modified '-H' switch                                       #
#   20. 7.2007   -- added slack??.? version detection for packages             #
#                     -> better compability with slackware 12.0...             #
#                        ...and it's changelog!                                #
#   10. 9.2007   -- added -f switch                                            #
#   10. 9.2007   -- reworked some stuff in "case ${PKG_LIST_MODE} in"          #
#   10. 9.2007   -- i'm losing my nerve, there's two openssl-0.9.7l patches in #
#                   10.2's changelog, when clearly the other should be         #
#                   openssl-solibs                                             #
#   13. 1.2008   -- removed bc dependency                                      #
#   20. 3.2008   -- minor stuff, cleanups, ncftpget&ncftpls no longer needed!  #
#   21. 3.2008   -- many things=)                                              #
#    7. 6.2008   -- removed lsof dependency                                    #
#    8. 6.2008   -- removed the (stdout & stderr) pipe detection,              #
#                   you have the -m switch=)                                   #
#                -- removed TTY variable                                       #
#                -- removed ps & stty from program dependency list             #
#   30. 6.2008   -- fixed $COLUMNS stuff                                       #
#   31. 7.2008   -- fixed regular expression in line 321                       #
#   25. 8.2008   -- learned about extended globbing=)                          #
#   21. 8.2009   -- as of now FILE_LIST is the only completely working mode    #
#   19. 9.2009   -- with slackware 13 we have to support .txz extension        #
#                   ...working on it                                           #
#    2010-2011   -- plenty of changes, i just haven't documented them=)        #
#                                                                              #
################################################################################
[ ${BASH_VERSINFO[0]} -lt 3 ] && {
  echo -e "error: bash version < 3, this script might not work properly!" 1>&2
  echo    "       you can bypass this check by commenting out lines $[${LINENO}-2]-$[${LINENO}+2]." 1>&2
  exit 1
}
set -u
# we need this to stay compatible with different versions of slackware!
if [ ${BASH_VERSINFO[0]} -eq 4 ]
then
  shopt -s compat31
fi
################################################################################
# OFFICIAL MIRRORS IN FINLAND (8.8.2006)                                       #
#                                                                              #
# TODO: we could try to use /etc/slackpkg/mirrors                              #
#                                                                              #
# feel free to replace these mirrors, but make sure that you have the correct  #
# path in the URL. slackware-<version> directories should be directly below    #
# these URLs.                                                                  #
################################################################################
declare -ra MIRRORS=(
  'http://ftp.belnet.be/packages/slackware/'
  'ftp://elektroni.phys.tut.fi/'
  'ftp://ftp.funet.fi/pub/mirrors/ftp.slackware.com/pub/'
  'ftp://openbsd.fi/slackware/'
)
# TODO: use same dirs as slackpkg (/var/cache/packages)
declare -r  WORK_DIR_ROOT="/var/cache/swsp"
# which packages not to upgrade
declare -ra UPDATE_BLACKLIST=("bash")
declare -r  UMASK="077"
declare -r  GPG_KEYRING="trustedkeys.gpg"
# 2.1.2011: use slackware.osuosl.org, the "another primary FTP site"
declare -r  MAIN_MIRROR="ftp://ftp.slackware.com/pub/slackware"
#declare -r  MAIN_MIRROR="ftp://slackware.osuosl.org/pub/slackware"
#declare -r  MAIN_MIRROR="http://ftp.belnet.be/packages/slackware"
################################################################################
# 20.3.2008: static error codes                                                #
################################################################################
declare -ri RET_OK=0
declare -ri RET_FAILED=1
declare -ri RET_ERROR=2
declare -ri RET_FERROR=3
declare -r  PRIMARY_KEY_FINGERPRINT="EC56 49DA 401E 22AB FA67  36EF 6A44 63C0 4010 2233"
declare -r  SWSP="${0##*/}"
################################################################################
# PKG_LIST_MODE: ftp || ChangeLog || FILE_LIST                                 #
#                                                                              #
# FILE_LIST is a good method, since we can verify it's MD5 from CHECKSUMS.md5  #
# and verify CHECKSUMS.md5 with PGP                                            #
################################################################################
declare     PKG_LIST_MODE="FILE_LIST"
declare -a  PACKAGE
# UPDATES[] is used by process_packages(), security_update() &
# print_upgrade_summary() functions
declare -a  UPDATES=()
declare -a  UPGRADED_PACKAGES
declare -a  FAILED_PACKAGES
declare     ACTION=
declare     CHECKSUMS_VERIFIED=false
declare -r  YEAR=$(date +%Y)

# BOOLEANS
declare USE_SYSLOG=1
declare SHOW_DESCRIPTION=1
# TODO: rename variable
declare PRINT_WGET_OUTPUT=0
declare KERNEL_UPGRADE=0
declare SELECT_UPDATES_INDIVIDUALLY=0
declare DRY_RUN=0
declare MONOCHROME=0
declare SKIP_VERSION_TEST=0
# /BOOLEANS

export PATH="/bin:/usr/bin:/sbin"
export LANG=en_US
# LANG=C   ?
# LC_ALL=C ?
export LC_COLLATE=C
umask "${UMASK}" || {
  echo "error at line $[${LINENO}-1], couldn't change umask!" 1>&2
  exit ${RET_FAILED}
}
# from WGET(1) version 1.12:
declare -ra WGET_ERRORS=(
  "No problems occurred"
  "Generic error code"
  "Parse error"
  "File I/O error"
  "Network failure"
  "SSL verification failure"
  "Username/password authentication failure"
  "Protocol errors"
  "Server issued an error response"
)
################################################################################
function register_prog() {
  # this function checks that we have all the required commands available.
  #
  # $1 = command
  #
  # RET_OK if all went well
  # RET_FAILED in case of command not found
  #
  # NOTE: we could also try to use the command_not_found_handle functionality.

  # references:
  #
  # http://tldp.org/LDP/abs/html/internal.html#HASHCMDREF
  # http://wiki.bash-hackers.org/scripting/style#availability_of_commands
  # https://www.gnu.org/s/bash/manual/html_node/Bourne-Shell-Builtins.html#index-hash-117

  if ! hash "${1}" 2>/dev/null
  then
    printf "%s(): error: Command not found in PATH: %s\n" "${FUNCNAME}" "${1}" >&2
    return ${RET_FAILED}
  fi

  return ${RET_OK}
} # register_prog()
################################################################################
for PROGRAM in gpg gpgv md5sum upgradepkg awk gawk sed grep echo rm mkdir egrep eval cut wget cat column date
do
  register_prog "${PROGRAM}" || exit ${RET_FAILED}
done
declare COLUMNS="${COLUMNS:-`tput cols 2>/dev/null`}"
#declare ARCH=`uname -m`
# TODO: we might get problems with backwards compability when slackware (32bit) upgrades to i686...
#case "${ARCH}" in
case "${MACHTYPE%%-*}" in
  "x86_64")	SLACKWARE="slackware64"	;;
  i?86)		SLACKWARE="slackware"	;;
  *)
    echo "error: couldn't determine architecture." 1>&2
    exit ${RET_FAILED}
  ;;
esac
declare VERSION=`sed 's/^.*[[:space:]]\([0-9]\+\.[0-9]\+\).*$/\1/' /etc/slackware-version 2>/dev/null`
declare WORK_DIR="${WORK_DIR_ROOT}/${VERSION}"
################################################################################
# version_checker() & do_version_check() ripped from Gary_Lerhaupt@Dell.com    #
# http://lists.us.dell.com/pipermail/dkms-devel/2004-July/000142.html          #
################################################################################
version_checker() {
  local ver1=$1
  while [ `echo $ver1 | egrep -c [^0123456789.]` -gt 0 ]; do
    char=`echo $ver1 | sed 's/.*\([^0123456789.]\).*/\1/'`
    char_dec=`echo -n "$char" | od -b | head -1 | awk {'print $2'}`
    ver1=`echo $ver1 | sed "s/$char/.$char_dec/g"`
  done
  local ver2=$2
  while [ `echo $ver2 | egrep -c [^0123456789.]` -gt 0 ]; do
    char=`echo $ver2 | sed 's/.*\([^0123456789.]\).*/\1/'`
    char_dec=`echo -n "$char" | od -b | head -1 | awk {'print $2'}`
    ver2=`echo $ver2 | sed "s/$char/.$char_dec/g"`
  done
  ver1=`echo $ver1 | sed 's/\.\./.0/g'`
  ver2=`echo $ver2 | sed 's/\.\./.0/g'`
  do_version_check "$ver1" "$ver2"
} # version_checker()
################################################################################
do_version_check() {
  [ "$1" == "$2" ] && return 10
  ver1front=`echo $1 | cut -d "." -f -1`
  ver1back=`echo $1 | cut -d "." -f 2-`
  ver2front=`echo $2 | cut -d "." -f -1`
  ver2back=`echo $2 | cut -d "." -f 2-`
  if [ "$ver1front" != "$1" ] || [ "$ver2front" != "$2" ]; then
    [ "$ver1front" -gt "$ver2front" ] && return 11
    [ "$ver1front" -lt "$ver2front" ] && return 9
    [ "$ver1front" == "$1" ] || [ -z "$ver1back" ] && ver1back=0
    [ "$ver2front" == "$2" ] || [ -z "$ver2back" ] && ver2back=0
    do_version_check "$ver1back" "$ver2back"
    return $?
  else
    [ "$1" -gt "$2" ] && return 11 || return 9
  fi
} # do_version_check()
################################################################################
function get_file() {
  ##############################################################################
  # 20.3.2008: simplified this function                                        #
  #  5.4.2008: TODO: detect if we're called from a function, and apply the '  '#
  #                  prefix accordingly                                        #
  # input:                                                                     #
  #   $1 = url_to_file                                                         #
  # return                                                                     #
  #   0: ok                                                                    #
  #   1: failed (for any reason)                                               #
  ##############################################################################
  local -i RET=0
  local -i BYTES=0
  local -i WGET_RET=0
  local -a TIMESTAMPS

  if [[ "${1}" =~ "^([a-z]+)://([^/]+)/+(.+)/+([^/]+)$" ]]
  then
    #            PROTO---   HOST---  DIR-  FILE---                             #
    ############################################################################
    local PROTO="${BASH_REMATCH[1]}"
    local HOST="${BASH_REMATCH[2]}"
    local DIR="${BASH_REMATCH[3]}"
    local FILE="${BASH_REMATCH[4]}"
  else
    echo "${FUNCNAME}(): ${ERR}error${RST}: malformed url!" 1>&2
    return ${RET_FAILED}
  fi

  ##############################################################################
  # NOTE: ADD FILE://                                                          #
  ##############################################################################

  case "${PROTO}" in
    # TODO: https
    "ftp"|"http")
      TIMESTAMPS=()
      echo -e "  fetching file: \`${HL}${FILE}${RST}' from: ${HL}${HOST}${RST}" 1>&3
      # if the file already exists, take the timestamp. we use this to detect
      # if wget downloaded a newer file.
      if [ -f "${WORK_DIR}/${FILE}" ]
      then
	TIMESTAMPS[${#TIMESTAMPS[*]}]=`stat -c %Y "${WORK_DIR}/${FILE}"`
      fi
      ##########################################################################
      # wget(1):                                                               #
      # When running Wget with -N, with or without -r, the decision as to      #
      # whether or not to download a newer copy of a file depends on the local #
      # and remote timestamp and size of the file.                             #
      ##########################################################################
      # TODO: use --cut-dirs with wget
      wget -nv --directory-prefix="${WORK_DIR}" --timestamping "${1}" 2>&5
      WGET_RET=${?}
      if [ -f "${WORK_DIR}/${FILE}" ]
      then
	TIMESTAMPS[${#TIMESTAMPS[*]}]=`stat -c %Y "${WORK_DIR}/${FILE}"`
      fi

      if [ ${WGET_RET} -eq 0 ]
      then
        # detect whether we downloaded anything
        if [ ${#TIMESTAMPS[*]} -eq 2 ] && [ ${TIMESTAMPS[0]} -eq ${TIMESTAMPS[1]} ]
	then
          echo "  server file no newer than local file" 1>&3
	else
          BYTES=`stat -c%s "${WORK_DIR}/${FILE}"`
          echo -e "  download ${HL}succeeded${RST} (${HL}${BYTES}${RST} bytes)" 1>&3
	fi
      else
        echo -e "  download ${ERR}failed${RST}, wget returned ${WGET_RET} (\"${WGET_ERRORS[${WGET_RET}]}\")!" 1>&3
        RET=${RET_FAILED}
      fi
    ;;
    *)
      echo "${FUNCNAME}(): error: invalid protocol \`${PROTO}' -- only HTTP & FTP currently supported!" 1>&2
      RET=${RET_FAILED}
    ;;
  esac # case ${PROTO}

  return ${RET}
} # get_file()
################################################################################
function get_files() {
  ##############################################################################
  # input                                                                      #
  #   $* = urls                                                                #
  ##############################################################################
  while [ -n "${1}" ]
  do
    get_file "${1}" || return ${RET_FAILED}
    shift 1
  done
  return ${RET_OK}
} # get_files()
################################################################################
function md5_verify() {
  # $1 = how to find it in CHECKSUMS.md5
  # $2 = the actual file to verify
  #
  # return:
  #   $RET_FAILED
  #   $RET_FERROR if CHECKSUMS.md5 can't be verified
  # 25.6.2011: TODO: change the SIGFILE_BASENAME variable name
  local -a MD5SUMS
  local    SIGFILE="${1}"
  local    SIGFILE_BASENAME="${2}"
  local -i RET

  # few checks
  if [ ! -f "${WORK_DIR}/CHECKSUMS.md5" ]
  then
    get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/CHECKSUMS.md5" || {
      echo "  ${FUNCNAME}(): error: CHECKSUMS.md5 missing and failed to download!" 1>&2
      return ${RET_FERROR}
    }
  elif [ ! -f "${WORK_DIR}/CHECKSUMS.md5.asc" ]
  then
    get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/CHECKSUMS.md5" || {
      echo "  ${FUNCNAME}(): error: CHECKSUMS.md5.asc missing and failed to download!" 1>&2
      return ${RET_FERROR}
    }
  fi
  [ ! -f "${WORK_DIR}/${SIGFILE_BASENAME}" ] && {
    echo "  ${FUNCNAME}(): error: file \`${SIGFILE_BASENAME}' does not exist!" 1>&2
    return ${RET_FAILED}
  }
  ##############################################################################
  # if we can't verify CHECKSUMS file, we can't use it to compare MD5s         #
  # so we'll return with fatal error and abort the whole upgrade procedure     #
  ##############################################################################
  # if either of these is true...                                              #
  if \
    ${CHECKSUMS_VERIFIED} || \
    gpg_verify "${WORK_DIR}/CHECKSUMS.md5.asc" "${PRIMARY_KEY_FINGERPRINT}"
  then
    #echo "  ${FUNCNAME}(): DEBUG: CHECKSUMS verified (second row)" 1>&2
    CHECKSUMS_VERIFIED=true
  else
    echo "${FUNCNAME}(): error: can't verify the CHECKSUMS file!" 1>&2
    return ${RET_FERROR}
  fi

  echo -en "  comparing MD5 checksums for file \`${HL}${SIGFILE_BASENAME}${RST}'..." 1>&3
  # 19.9.2009: why not use awk?                                                #
  # 14.1.2010: old: `sed -n "/\/${SIGFILE}$/s/^\(.*\)[[:space:]]\+.*$/\1/p" "${WORK_DIR}/CHECKSUMS.md5" 2>/dev/null`
  # 14.1.2010: new: sed -n 's:^\([0-9a-f]\{32\}\)[[:space:]]\+.*'"${SIGFILE}"'$:\1:p' "${WORK_DIR}/CHECKSUMS.md5"

  #echo "${FUNCNAME}(): DEBUG: SIGFILE=\"${SIGFILE}\""
  # example line from CHECKSUMS.md5:
  # d10a06f937e5e6f32670d6fc904120b4  ./patches/packages/linux-2.6.29.6-3/kernel-modules-2.6.29.6-i486-3.txz.asc
  # $SIGFILE could include /'s so we use `:' with sed                          #
  MD5SUMS=(
    $( sed -n 's:^\([0-9a-f]\{32\}\)[[:space:]]\+\..*'"${SIGFILE}"'$:\1:p' "${WORK_DIR}/CHECKSUMS.md5" 2>/dev/null )
    $( md5sum "${WORK_DIR}/${SIGFILE_BASENAME}" 2>/dev/null | awk '{print $1}' )
  )
  # sanity check... better safe than sorry                                     #
  if [ ${#MD5SUMS[*]} -ne 2 -o \
       ${#MD5SUMS[0]} -ne 32 -o \
       ${#MD5SUMS[1]} -ne 32 ]
  then
    ############################################################################
    # NOTE: OF COURSE THIS SHOULD NEVER HAPPEN!                                #
    ############################################################################
    echo -e "${ERR}error${RST}!" 1>&3
    echo "${FUNCNAME}(): error between lines $[LINENO-12]-$[LINENO-9]!" 1>&2
    return ${RET_ERROR}
  fi
  if [ "x${MD5SUMS[0]}" = "x${MD5SUMS[1]}" ]
  then
    ############################################################################
    # SINCE BOTH MD5'S ARE THE SAME, WE RANDOMIZE WHICH ONE TO PRINT=)         #
    ############################################################################
    #echo -e "${HL}match${RST}!\n    MD5 checksum: ${HL}${MD5SUMS[$[${RANDOM}%2]]}${RST}" 1>&3
    echo -e "${HL}match${RST} (MD5: ${HL}${MD5SUMS[$[RANDOM%2]]}${RST})!" 1>&3
    RET=${RET_OK}
  else
    echo -e "${ERR}mismatch${RST}!" 1>&3
    RET=${RET_FAILED}
  fi
  return ${RET}
} # md5_verify
################################################################################
function gpg_verify() {
  ##############################################################################
  # input:                                                                     #
  #   $1 = file                                                                #
  #   $2 = primary key fingerprint                                             #
  # return                                                                     #
  #   0: file successfully verified                                            #
  #   1: something wen't wrong                                                 #
  ##############################################################################
  local    SIGFILE
  local    FILE_TO_VERIFY
  local -i RET

  # <just_in_case>                                                             #
  if [ "x${1:(-4)}" = "x.asc" ]
  then
    FILE_TO_VERIFY="${1%.asc}"
    SIGFILE="${1}"
  else
    FILE_TO_VERIFY="${1}"
    SIGFILE="${1}.asc"
  fi
  # </just_in_case>                                                            #

  #echo "${FUNCNAME}(): DEBUG:"
  #echo "  FILE_TO_VERIFY=${FILE_TO_VERIFY}"
  #echo "  SIGFILE=${SIGFILE}"
  #echo "${FUNCNAME}(): DEBUG: \${1:(-4)}: ${1:(-4)}"

  if [ ! -f "${FILE_TO_VERIFY}" ]
  then
    echo -e "${FUNCNAME}(): ${ERR}error${RST}: file \`${FILE_TO_VERIFY}' does not exist!" 1>&2
    return ${RET_FAILED}
  elif [ ! -f "${SIGFILE}" ]
  then
    echo -e "${FUNCNAME}(): ${ERR}error${RST}: sigfile \`${SIGFILE}' does not exist!" 1>&2
    return ${RET_FAILED}
  fi
  echo -e "  verifying \`${HL}${FILE_TO_VERIFY##*/}${RST}' with PGP..." 1>&3
  # print a newline so gpgv output is on it's own lines...
  #(( ${PRINT_WGET_OUTPUT} )) && echo -n $'\n' 1>&3
  ##############################################################################
  # GPG FAQ:                                                                   #
  # If the signature file has the same base name as the package file,          #
  # the package can also be verified by specifying just the signature          #
  # file, as GnuPG will derive the package's file name from the name           #
  # given (less the .sig or .asc extension).                                   #
  ##############################################################################
  echo "verifying ${FILE_TO_VERIFY} with gpgv" 1>&4
  # NOTE:
  #   we could leave the gpgv output even without PRINT_WGET_OUTPUT, since it
  #   has useful information. namely the timestamp.
  #   "gpgv: Signature made Sat 16 Jun 2012 07:21:45 PM EEST using DSA key ID 40102233"

  # old version (output -> fd#5)
  #gpgv --quiet --logger-fd 5 "${SIGFILE}"

  # current, quiet output always since it's quite useful.
  gpgv --quiet "${SIGFILE}"
  RET=${?}
  #RET=${PIPESTATUS[0]}
  case "${RET}" in
    0)
      #(( ! ${PRINT_WGET_OUTPUT} )) && echo -e "${HL}ok${RST}!" 1>&3
      true
    ;;
    *)
      echo -e "${ERR}failed${RST} (code ${RET})!" 1>&3
      # WE CHANGE THE NON-ZERO RETURN CODE TO 1, since this function can't     #
      # return with fatal error                                                #
      RET=${RET_FAILED}
    ;;
  esac
  return ${RET}
} # gpg_verify()
################################################################################
function verify_package() {
  ##############################################################################
  # this function checks the MD5 from CHECKSUMS.md5 and runs gpg_verify()      #
  #                                                                            #
  # input                                                                      #
  #   $1 = dir/package-version-architecture-revision.extension                 #
  # return                                                                     #
  #   0: $RET_OK = package successfully verified                               #
  #   1: $RET_FAILED = invalid package(?)... on with the show                  #
  #        -> upgrade_package_from_mirror() tries another mirror               #
  #   2: $RET_ERROR = md5sum error, or couldn't fetch .asc                     #
  #        -> upgrade_package_from_mirror() skips the whole package            #
  #   3: $RET_FERROR = fatal error, can't upgrade ANY packages!                #
  ##############################################################################
  local    FILE
  local    SIGFILE="${1}.asc"
  local    SIGFILE_BASENAME="${SIGFILE##*/}"

  #echo "${FUNCNAME}(): DEBUG: \$1=${1} SIGFILE=${SIGFILE} SIGFILE_BASENAME=${SIGFILE_BASENAME}"

  # can't verify this package at all? return RET_ERROR and go on to the next p #
  [ -f "${WORK_DIR}/${SIGFILE_BASENAME}" ] || \
    get_file "${MAIN_MIRROR}/${FTP_PATH_SUFFIX}/${SIGFILE}" || \
      return ${RET_ERROR}

  # do we have the files, do they verify?                                      #
  # 11.10.2009: this is getting too complicated=)                              #
  # 25.6.2011: TODO: clean up!
  #if \
  #  # we MUST have the files AND either of the two criterias true              #
  #  [ -f "${WORK_DIR}/CHECKSUMS.md5" -a -f "${WORK_DIR}/CHECKSUMS.md5.asc" ] && \
  #  (
  #    ${CHECKSUMS_VERIFIED} || \
  #    # in case the local files are borked                                     #
  #    gpg_verify "${WORK_DIR}/CHECKSUMS.md5.asc" "${PRIMARY_KEY_FINGERPRINT}"
  #  )
  #then
  #  # gpg_verify returned 0, or already verified                               #
  #  echo "  ${FUNCNAME}(): DEBUG: CHECKSUMS verified (first row)" 1>&2
  #  CHECKSUMS_VERIFIED=true
  #else
  #  rm -f "${WORK_DIR}/CHECKSUMS.md5" "${WORK_DIR}/CHECKSUMS.md5.asc"
  #  for FILE in "CHECKSUMS.md5" "CHECKSUMS.md5.asc"
  #  do
  #    # no CHECKSUMS = no MD5s = no updates = FATAL ERROR!                     #
  #    get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/${FILE}" || return ${RET_FERROR}
  #  done
  #  CHECKSUMS_VERIFIED=false
  #fi

  # are the files new enough?                                                  #
  if ! grep --quiet "${SIGFILE}$" "${WORK_DIR}/CHECKSUMS.md5" 2>/dev/null
  then
    # no? get the new ones...                                                  #
    echo -e "  ${HL}notice${RST}: current \`CHECKSUMS.md5' doesn't include a hash for \`${SIGFILE_BASENAME%-*-*}', downloading a new copy"
    rm -fv "${WORK_DIR}/CHECKSUMS.md5" "${WORK_DIR}/CHECKSUMS.md5.asc" 1>&5
    for FILE in "CHECKSUMS.md5" "CHECKSUMS.md5.asc"
    do
      # no CHECKSUMS = no MD5s = no updates = FATAL ERROR!                     #
      get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/${FILE}" || return ${RET_FERROR}
    done
    CHECKSUMS_VERIFIED=false
    # we should now have the newest CHECKSUMS, does it include a hash for the  #
    # current package?                                                         #
    grep --quiet "${SIGFILE}$" "${WORK_DIR}/CHECKSUMS.md5" 2>/dev/null || {
      echo -e "${FUNCNAME}(): ${WRN}warning${RST}: CHECKSUMS.md5 doesn't include hash for \`${SIGFILE_BASENAME}'!"
      # we can't upgrade the package without the hash                          #
      return ${RET_ERROR}
    }
  fi

  # we search with the full path (e.g.: "linux-2.6.27.31/kernel-modules-smp-2.6.27.31_smp-i686-2.tgz.asc")
  md5_verify "${1}" "${1##*/}"							|| return ${RET_FAILED}
  md5_verify "${SIGFILE}" "${SIGFILE_BASENAME}"					|| return ${RET_FAILED}
  gpg_verify "${WORK_DIR}/${SIGFILE_BASENAME}" "${PRIMARY_KEY_FINGERPRINT}"	|| return ${RET_FAILED}
  return ${RET_OK}
} # verify_package()
################################################################################
# TODO: this function is not currently used at all...
function print_update_description() {
  ##############################################################################
  # TODO: this could/should be done with just plain awk                        #
  ##############################################################################
  local    PACKAGE_NAME
  local -i J
  local    AWK_SEARCH
  grep -q "patches/packages/${1//./\.}\.tgz" "${WORK_DIR}/ChangeLog.txt" || return ${RET_FAILED}
  PACKAGE_NAME=${1%-*-*-*}
  echo -en "  +-[ ${HL}${PACKAGE_NAME}${RST} ]"
  [ ${COLUMNS} -lt 83 ] && local K=$[83-${COLUMNS}]
  for ((J=0; J<=$[74-${#PACKAGE_NAME}-${K-0}]; J++))
  do
    echo -n $'-'
  done
  echo -n $'\n'
  AWK_SEARCH=`echo "${1}" | sed 's/+/\\\+/g;s/\./\\\./g'`
  awk -v columns="${COLUMNS}" '/patches\/packages\/'"${AWK_SEARCH}"'/ {
    do {
      if(length>columns-4)
      $0 = substr($0, 1, columns-7)"..."
      print "  |",$0
      getline
    } while ($0 !~ /+--------------------------+/ && $0 !~ /patches\/packages\//)
  }' "${WORK_DIR}/ChangeLog.txt"
  return ${?}
} # print_update_description()
################################################################################
function upgrade_package_from_mirror() {
  ##############################################################################
  # $1 = package-version-architecture-revision                                 #
  # $2 = <size> (optional)                                                     #
  # return                                                                     #
  #   0: package successfully upgraded                                         #
  #   1: error       -- cannot upgrade current package                         #
  #   2: fatal error -- cannot upgrade any packages                            #
  ##############################################################################
  local -i I
  local -i J=0
  local    PACKAGE_NAME
  local    AWK_SEARCH
  local    PACKAGE="${1}"
  local    PACKAGE_BASENAME="${PACKAGE##*/}"
  ##############################################################################
  # NOTE: FIX ME!!! ADD LOCAL PACKAGE CHECK!                                   #
  ##############################################################################
  [ -f "${WORK_DIR}/${PACKAGE}" ] && rm -fv "${WORK_DIR}/${PACKAGE}" 1>&5
  ##############################################################################
  # show package description if possible                                       #
  ##############################################################################
  (( ${SHOW_DESCRIPTION} )) && grep -q "patches/packages/${1//./\.}\.tgz" "${WORK_DIR}/ChangeLog.txt" 2>/dev/null && {
    PACKAGE_NAME=${1%-*-*-*}
    echo -en "  +-[ ${HL}${PACKAGE_NAME}${RST} ]"
    [ ${COLUMNS} -lt 83 ] && local K=$[83-${COLUMNS}]
    for ((J=0; J<=$[74-${#PACKAGE_NAME}-${K-0}]; J++))
    do
      echo -n $'-'
    done
    echo -n $'\n'
    AWK_SEARCH=`echo "${PACKAGE}" | sed 's/+/\\\+/g;s/\./\\\./g'`
    awk -v columns="${COLUMNS}" '/patches\/packages\/'"${AWK_SEARCH}"'/ {
      do {
        if(length>columns-4)
        $0 = substr($0, 1, columns-7)"..."
        print "  |",$0
        getline
      } while ($0 !~ /+--------------------------+/ && $0 !~ /patches\/packages\//)
    }' "${WORK_DIR}/ChangeLog.txt"
  }

  for ((I=0; I<$[${#MIRRORS[*]}]; I++))
  do
    get_file "${MIRRORS[${I}]}/${FTP_PATH_SUFFIX}/${PACKAGE}" || continue
    # 21.3.2008: here we go with the static return codes=)                     #
    # 21.8.2009: strip possible directories                                    #
    #echo "${FUNCNAME}(): DEBUG: PACKAGE=\"${PACKAGE}\" PACKAGE_BASENAME=\"${PACKAGE_BASENAME}\""
    verify_package "${PACKAGE}"
    case ${?} in
      ${RET_OK})
        # dry-run first to check for any problems
	echo -n $'  dry-run:\n    ' 1>&3
	upgradepkg --dry-run "${WORK_DIR}/${PACKAGE_BASENAME}" || return ${RET_FAILED}
	if (( ${DRY_RUN} ))
	then
	  # dry-run mode, so we stop here.
	  return ${RET_OK}
	else
          echo -e "  ${HL}notice${RST}: logging the upgrade process to \`${WORK_DIR}/${PACKAGE_BASENAME}.log'." 1>&3
          echo -en "  upgrading package..." 1>&3
	  #upgradepkg "${WORK_DIR}/${PACKAGE_BASENAME}" &> "${WORK_DIR}/${PACKAGE_BASENAME}.log" && {
	  upgradepkg "${WORK_DIR}/${PACKAGE_BASENAME}" | tee "${WORK_DIR}/${PACKAGE_BASENAME}.log" 1>&5
	  if [ ${PIPESTATUS[0]} -eq 0 ]
	  then
            echo -e "${HL}ok${RST}!" 1>&3
            ####################################################################
	    # NOTE: REMOVE LOCAL PACKAGE?                                      #
            ####################################################################
	    #UPGRADED_PACKAGES[${#UPGRADED_PACKAGES[*]}]="${PACKAGE_BASENAME}"
	    UPGRADED_PACKAGES+=("${PACKAGE_BASENAME}")
	    return ${RET_OK}
	  else
	    echo -e "${ERR}FAILED${RST}, check the log in \`${HL}${WORK_DIR}/${PACKAGE_BASENAME}.log${RST}'!" 1>&3
            return ${RET_FAILED}
	  fi # if [ ${PIPESTATUS[0]} -eq 0 ]
	fi # if (( ${DRY_RUN} ))
      ;;
      ${RET_FAILED})
        ########################################################################
        # NOTE: TRY ANOTHER MIRROR                                             #
        #       SHOULD THIS MESSAGE BE REMOVED?!                               #
        ########################################################################
        echo -en "  ${ERR}error${RST}: package \`${HL}${1%-*-*-*}${RST}' is not authentic, removing it..." 1>&3
        rm -fv "${WORK_DIR}/${PACKAGE}.tgz" 1>&5 && echo -e "${HL}done${RST}!" 1>&3 || echo -e "${ERR}FAILED${RST}?!" 1>&3
        continue
      ;;
      ${RET_ERROR})  return ${RET_FAILED} ;;
      ${RET_FERROR}) return ${RET_FERROR} ;; # cannot upgrade any packages
      #3|4) return 1 ;;
    esac # verify_package() -- case
  done # for ((I=0; I<=$[${#MIRRORS[*]}-1]; I++))
  ##############################################################################
  # IF WE GOT THIS FAR, IT MEANS SOMETHING WEN'T WRONG!                        #
  ##############################################################################
  return ${RET_FAILED}
} # upgrade_package_from_mirror()
################################################################################
function architecture_check() {
  # $1 = machine architecture
  # $2 = package architecture
  # $3 = package name
  [ ${#} -ne 2 ] && {
    echo -e "${FUNCNAME}(): ${ERR}error${RST}: wrong amount of parameters, this shouldn't happen!"
    return ${RET_ERROR}
  }

  if [ "${1}" = "noarch" ]
  then
    # package isn't architecture dependent (confs, docs, .php etc...)
    return ${RET_OK}
  elif [ "${2}" = "kernel-headers" -a "${1}" = "x86" ]
  then
    # kernel headers (x86) ... it's the same for x86 and x86_64 for some reason.
    return ${RET_OK}
  elif [[ "${MACHTYPE%%-*}" =~ "^i.86$" && "${1}" =~ "^i.86$" ]]
  then
    # x86 architecture
    return ${RET_OK}
  elif [ "${MACHTYPE%%-*}" = "x86_64" -a "${1}" = "x86_64" ]
  then
    # x86_64 architecture
    return ${RET_OK}
  else
    #echo -e "${FUNCNAME}(): ${WRN}warning${RST}: wrong architecture (${2} != ${1})!"
    return ${RET_FAILED}
  fi

  return ${RET_ERROR}
} # architecture_check()
################################################################################
function find_ssa() {
  # this function tries to find the SSA ID for package $1
  local -a SSAS
  local    SSA

  # this means you haven't run the -a parameter, no worries, this is not that
  # important
  [ ! -d "${WORK_DIR}/advisories/${YEAR}" ] && return ${RET_FAILED}

  [ ${#} -ne 1 -o -z "${1}" ] && {
    echo "${FUNCNAME}(): parameter error!" 1>&2
    return ${RET_ERROR}
  }
  SSAS=(`grep -l "${1}" "${WORK_DIR}/advisories/${YEAR}/SSA"* 2>/dev/null`)
  if [ ${#SSAS[*]} -eq 0 ]
  then
    # for some updates, there just isn't advisory available. see
    # https://twitter.com/#!/volkerdi/status/85028087984685056 for an example=)

    #echo "${FUNCNAME}(): SSA ID not found." 1>&3
    return ${RET_FAILED}
  elif [ ${#SSAS[*]} -gt 1 ]
  then
    echo "${FUNCNAME}(): warning: more than one SSA ID found for \`${1}'." 1>&2
    return ${RET_FAILED}
  elif [ ${#SSAS[*]} -eq 1 ]
  then
    [[ "${SSAS[0]}" =~ "^.+/(SSA:[0-9-]+)\.txt$" ]] && {
      SSA="${BASH_REMATCH[1]}"
      echo "${SSA}"
      return ${RET_OK}
    }
  fi

  return ${RET_FAILED}
} # find_ssa()
################################################################################
function process_packages() {
  ##############################################################################
  # PROCESS THE LIST BEFORE ACTUAL UPGRADE                                     #
  ##############################################################################
  local -a PACKAGES=( ${*} )
  local    PACKAGE_BASENAME
  local    PKG_NAME
  local    PKG_VERSION
  local    PKG_ARCH
  local    LOCAL_PKG_NAME
  local    LOCAL_PKG_VERSION
  local    LOCAL_PKG_REV
  local    GLOB
  local -a LOCAL_FILES
  local    BLACKLISTED
  local -i I

  pushd /var/log/packages &>/dev/null || return ${RET_FAILED}

  echo -e "${FUNCNAME}(): processing packages" 1>&3
  for ((I=0; I<${#PACKAGES[*]}; I++))
  do
    PACKAGE_BASENAME="${PACKAGES[${I}]##*/}"
    split_package_name "${PACKAGE_BASENAME}" "PKG" || {
      echo -e "${FUNCNAME}(): ${WRN}warning${RST}: this probably means that there was an error while reading/parsing the packages list"
      #echo "${FUNCNAME}(): DEBUG: ${PACKAGES[${I}]##*/}"
      continue
    }
    # check if the package is of correct architecture
    architecture_check "${PKG_ARCH}" "${PKG_NAME}" || {
      echo -e "${FUNCNAME}(): ${WRN}warning${RST}: package \`${PACKAGE_BASENAME}' failed the architecture check (${PKG_ARCH} vs. ${MACHTYPE%%-*}), skipping!"
      continue
    }
    ############################################################################
    # 25.8.2008: ok, so this is kinda ugly too, but better than ls|grep ;)     #
    #            since we can't use (s or )s in a array declaration            #
    #    update: if we don't enable extglob in the beginning of the script     #
    #            bash thinks our array declaration is broken, so we must use   #
    #            $GLOB to trick bash                                           #
    #                                                                          #
    # +(pattern-list)                                                          #
    #     Matches one or more occurrences of the given patterns.               #
    #                                                                          #
    # 19.9.2009: with local files, we don't know the file extension            #
    ############################################################################
    GLOB="${PKG_NAME}-+([^-])-+([^-])-+([^-])"
    shopt -s extglob nullglob
    LOCAL_FILES=(${GLOB})
    shopt -u extglob nullglob

    # no such package installed, no need to update
    [ ${#LOCAL_FILES[*]} -eq 0 ] && continue

    [ ${#LOCAL_FILES[*]} -gt 1 ] && {
      echo -e "${FUNCNAME}(): ${WRN}warning${RST}:\n  multiple packages with the same name,\n  refusing to guess which one to upgrade (${HL}${PKG_NAME}${RST})!" 1>&2
      continue
    }
    split_package_name "${LOCAL_FILES[0]}" "LOCAL_PKG"
    if [ "x${PKG_NAME}" != "x${LOCAL_PKG_NAME}" ]
    then
      echo "${FUNCNAME}(): unknown error at line $[LINENO-2]!" 1>&2
      continue
    fi
    if (( ${SELECT_UPDATES_INDIVIDUALLY} ))
    then
      # remember: print local and remote versions...
      # prompt y/n
      #echo "${FUNCNAME}(): DEBUG: PACKAGES[\$I]=${PACKAGES[${I}]}"
      [ "x${PKG_VERSION}" = "x${LOCAL_PKG_VERSION}" -a "x${PKG_REV}" = "x${LOCAL_PKG_REV}" ] && continue
      echo "package details:"
      echo    "  update [$[${I}+1]/${#PACKAGES[*]}] ${HL}${PKG_NAME}${RST}:"
      #echo -e "    name:\t${PKG_NAME}"
      echo -e "    available:"
      echo -e "      version:\t${HL}${PKG_VERSION}${RST}"
      echo -e "      revision:\t${PKG_REV}"
      echo    "    current:"
      echo -e "      version:\t${LOCAL_PKG_VERSION}"
      echo -e "      revision:\t${LOCAL_PKG_REV}"
      until [ "x${REPLY}" = "xy" -o "x${REPLY}" = "xn" ]
      do
        read -p "upgrade package \`${PKG_NAME}'? y/n: " -n 1 REPLY
        case "${REPLY}" in
          "y")
            echo "es"
            UPDATES[${#UPDATES[*]}]="${PACKAGES[${I}]}"
          ;;
          "n") echo "o" ;;
          *)   echo -n $'\n' ;;
        esac
      done
      unset -v REPLY
    # select updates automatically
    else
      ############################################################################
      # check if the package is "blacklisted", something that you don't want to  #
      # upgrade with this script.                                                #
      #                                                                          #
      # TODO: include slackpkg's blacklist (/etc/slackpkg/blacklist)             #
      ############################################################################
      for BLACKLISTED in ${UPDATE_BLACKLIST[*]}
      do
        [ "x${PKG_NAME}" = "x${BLACKLISTED}" ] && {
          echo -e "${FUNCNAME}(): ${HL}notice${RST}: skipping blacklisted package \`${HL}${PKG_NAME}${RST}'!" 1>&3
          continue 2
        }
      done
      ############################################################################
      # SLACKWARE VERSION DETECTION                                              #
      # seamonkey-1.0.6-i486-1_slack11.0.tgz and others in slackware 12.0        #
      # ChangeLog                                                                #
      # NOTE: 4.12.2011: added "_?" to regex because of:                         #
      # ftp://ftp.slackware.com/pub/slackware/slackware-13.37/patches/packages/make-3.82-i486-3_slack_13.37.txz
      ############################################################################
      if \
	[[ "${PKG_REV}" =~ "^.+slack_?(.+)$" ]] && \
	  [ "x${BASH_REMATCH[1]}" != "x${VERSION}" ]
      then
        echo -e "${FUNCNAME}(): ${WRN}warning${RST}: skipping package \`${HL}${PKG_NAME}${RST}': revision = ${PKG_REV}!" 1>&2
        continue
      fi

      # exactly same version -> next
      # no need to run version_checker().
      # NOTE: we could also run updatepkg --dry-run here?
      if [ "x${PKG_VERSION}-${PKG_REV}" = "x${LOCAL_PKG_VERSION}-${LOCAL_PKG_REV}" ]
      then
	continue
      fi

      # if SKIP_VERSION_TEST is set and it's not the same exact version+revision,
      # add it to the update list
      if \
	(( ${SKIP_VERSION_TEST} )) && \
	  # TODO: we could have upgradepkg make the following decision.
	  [ "x${PKG_VERSION}-${PKG_REV}" != "x${LOCAL_PKG_VERSION}-${LOCAL_PKG_REV}" ]
      then
	UPDATES+=("${PACKAGES[I]}")
      else
        version_checker "${PKG_VERSION}" "${LOCAL_PKG_VERSION}"
        case "${?}" in
          ##########################################################################
          # LOCAL > REMOTE                                                         #
          ##########################################################################
          9)
            echo -e "${FUNCNAME}(): ${HL}notice${RST}: skipping package \`${HL}${PKG_NAME}${RST}' in favor of local version: ${HL}${LOCAL_PKG_VERSION}${RST} > ${PKG_VERSION}" 1>&3
            continue
          ;;
          ##########################################################################
          # LOCAL VERSION == REMOTE VERSION, WHAT ABOUT REVISION?                  #
          ##########################################################################
          10)
            version_checker "${PKG_REV}" "${LOCAL_PKG_REV}"
            ########################################################################
            # LOCAL REV > REMOTE REV || LOCAL REV == REMOTE REV                    #
            ########################################################################
            [ ${?} -ne 11 ] && continue
	    UPDATES+=("${PACKAGES[I]}")
          ;;
          ##########################################################################
          # LOCAL VERSION < REMOTE VERSION                                         #
          ##########################################################################
          11) UPDATES+=("${PACKAGES[I]}") ;;
        esac
      fi # if (( ${SKIP_VERSION_TEST} ))
    fi # if ${SELECT_UPDATES_INDIVIDUALLY}
  done # ((I=0; I<=$[${PACKAGES}-1]; I++))

  popd &>/dev/null

  echo -e "${FUNCNAME}(): done processing packages" 1>&3

  return ${RET_OK}
} # process_packages()
################################################################################
function print_upgrade_summary() {
  # this function prints summary about the upgraded packages. this is called
  # from security_update() function.
  local -i I
  local -i J

  # print a list of upgraded packages
  echo $'\nsummary:'
  echo -e "  [${HL}${#UPGRADED_PACKAGES[*]}${RST}/${#UPDATES[*]}] package(s) upgraded:"
  for ((
    I=0, J=1;
    I<${#UPGRADED_PACKAGES[*]};
    I++, J=I+1
  ))
  do
    # FIX ME!                                                                  #
    #echo "    ${J}: upgraded package ${PACKAGE[0]} to ${PACKAGE[1]}-${PACKAGE[3]}"
    #split_package_name "${UPGRADED_PACKAGES[${I}]}" "PKG"
    echo "    ${J}: upgraded ${UPGRADED_PACKAGES[${I}]}"
  done

  # if there were packages that failed to upgrade, print a list
  if [ "${#FAILED_PACKAGES[*]}" -ne 0 ]
  then
    echo -n $'\n'
    echo -e "  [${HL}${#FAILED_PACKAGES[*]}${RST}/${#UPDATES[*]}] package(s) ${ERR}failed${RST} to upgrade:"
    for ((
      I=0, J=1;
      I<${#FAILED_PACKAGES[*]};
      I++, J=I+1
    ))
    do
      echo "    ${J}: ${FAILED_PACKAGES[I]}"
    done
  fi

  return ${RET_OK}
} # print_upgrade_summary()
################################################################################
function security_update()
{
  # security_update() function                                                 #
  #                                                                            #
  # possible return values: return RET_OK || RET_FAILED                        #
  declare  FTP_PATH_SUFFIX="${SLACKWARE}-${VERSION}/patches/packages"
  local -i RET=${RET_OK}
  local -i I
  local -a PACKAGES
  local    PACKAGE_BASENAME
  local    MESSAGE

  local    PKG_NAME
  local    PKG_VERSION
  local    PKG_ARCH
  local    PKG_REV
  local    LOCAL_PKG_NAME
  local    LOCAL_PKG_VERSION
  local    LOCAL_PKG_ARCH
  local    LOCAL_PKG_REV

  #local -a UPDATES=()
  local    UPDATE
  local    UPDATE_BASENAME
  local    FILE
  local    SSA_ID
  ##############################################################################
  # read all the (newest) available patches to -> PACKAGES[]                   #
  #                                                                            #
  # 8.10.2009:                                                                 #
  #   many ways on doing this                                                  #
  #     - ChangeLog migth only include a directory of patches                  #
  #       -> sw 12.2 Tue Aug 18 14:35:23 CDT 2009                              #
  #     - ftp directory listing should be recursive in case of directories     #
  #       but we can't verify the list                                         #
  #     - FILE_LIST seems like the best option to go...                        #
  #     - PACKAGES.TXT                                                         #
  #                                                                            #
  ##############################################################################
  echo -e "${FUNCNAME}(): detected Slackware version: ${HL}${SLACKWARE}${RST}-${HL}${VERSION}${RST} (${HL}${MACHTYPE%%-*}${RST})" 1>&3
  case "${PKG_LIST_MODE}" in
    ############################################################################
    # ChangeLog's advantage is that we get to print the security description   #
    ############################################################################
    "DISABLEDChangeLog")
      echo "${FUNCNAME}(): please wait..." 1>&3
      ##########################################################################
      # replaced too complicated ncftpget thingie with wget --timestamping     #
      # (10.9.2007)                                                            #
      #                                                                        #
      ##########################################################################
      get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/ChangeLog.txt"
      [ ${?} -ne 0 ] && {
        echo "${FUNCNAME}(): error: an error occurred at line $[${LINENO}-2] while wgetting the changelog!" 1>&2
        return ${RET_FAILED}
      }
      echo -en "reading packages from \`${HL}ChangeLog.txt${RST}'..." 1>&3
      PACKAGES=(`read_packages_from_changelog`) || return ${RET_FAILED}
    ;;
    "FILE_LIST")
      echo "${FUNCNAME}(): please wait..." 1>&3
      # 21.8.2009: TODO: fix (to use) FTP_PATH_SUFFIX                          #

      # download the FILE_LIST and CHECKSUMS, so we can also verify the FILE_LIST
      for FILE in "patches/FILE_LIST" "CHECKSUMS.md5" "CHECKSUMS.md5.asc"
      do
        get_file "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/${FILE}"
      done
      CHECKSUMS_VERIFIED=false
      # verify the FILE_LIST first
      md5_verify "/patches/FILE_LIST" "FILE_LIST" || {
        return ${RET_FAILED}
      }
      echo -en "reading packages from \`${HL}FILE_LIST${RST}'..." 1>&3
      # example line:
      # -rw-r--r--  1 root root 20490788 2011-06-16 02:03 ./packages/seamonkey-2.1-i486-1_slack13.37.txz
      while read -a REPLY
      do
	if [ ${#REPLY[*]} -lt 8 ]
	then
          continue
	elif [[ "${REPLY[7]}" =~ "^\./packages/(.+\.t[gx]z)$" ]]
	then
          #PACKAGES[${#PACKAGES[*]}]="${BASH_REMATCH[1]}"
	  PACKAGES+=("${BASH_REMATCH[1]}")
	# detect kernel upgrade instructions from the file list
	elif [[ "${REPLY[7]}" =~ "^\./(packages/linux-.+/README)$" ]]
	then
	  KERNEL_UPGRADE_README="${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/patches/${BASH_REMATCH[1]}"
	fi
      done 0<"${WORK_DIR}/FILE_LIST"
    ;;
    *)
      echo "${FUNCNAME}(): error: invalid mode \`${PKG_LIST_MODE}'!"
      return ${RET_FAILED}
    ;;
  esac # "${PKG_LIST_MODE}"
  if [ ${#PACKAGES[*]} -eq 0 ]
  then
    cat 0<<-EOF 1>&3
	${ERR}failed${RST}!
	  0 packages found, this could mean three things:
	  a) there really is no security updates available
	  - or -
	  b) we couldn't access slackware's ftp
	  - or -
	  c) this script is broken
EOF
    # TODO: return OK or FAILED?
    return ${RET_FAILED}
  else
    echo -e "${HL}done${RST} (${HL}${#PACKAGES[*]}${RST} packages)!\n" 1>&3
  fi
  # update the advisory cache
  update_advisories

  process_packages ${PACKAGES[*]}

  # print the list of packages before beginning
  if [ ${#UPDATES[*]} -gt 0 ]
  then
    echo -e "\ngoing to update the following ${HL}${#UPDATES[*]}${RST} package(s):" 1>&3
    for ((I=0; I<${#UPDATES[*]}; I++))
    do
      UPDATE="${UPDATES[${I}]}"
      UPDATE_BASENAME="${UPDATE##*/}"
      echo "  ${UPDATE_BASENAME}" 1>&3
    done
    echo -n $'\n' 1>&3
  fi

  ##############################################################################

  for ((I=0; I<${#UPDATES[*]}; I++))
  do
    # 21.8.2009:                                                               #
    # UPDATE could be "linux-2.6.27.31/kernel-source-2.6.27.31_smp-noarch-2"   #
    # -> UPDATE_BASENAME would be "kernel-source-2.6.27.31_smp-noarch-2"       #
    UPDATE="${UPDATES[${I}]}"
    UPDATE_BASENAME="${UPDATE##*/}"
    split_package_name "${UPDATE_BASENAME}" "PKG"
    echo -e "${HL}update${RST} [$[${I}+1]/${#UPDATES[*]}]: updating package ${HL}${PKG_NAME}${RST} to ${HL}${PKG_VERSION}${RST}-${HL}${PKG_REV}${RST}" 1>&3

    # print the SSA ID, if it's available
    # NOTE:
    #   SSA ID's could be parsed during the pre-processing, but it would be
    #   nice to use associative arrays for that. but if we use those, we break
    #   the backwards compatibility.
    SSA_ID=`find_ssa "${UPDATE}"`
    [ -n "${SSA_ID}" ] && echo -e "  SSA ID: ${HL}${SSA_ID}${RST}" 1>&3

    # see if it might be a kernel update, so we can display a notice banner on the summary
    [[ "${PKG_NAME}" =~ "kernel" ]] && KERNEL_UPGRADE=1

    ############################################################################
    # NOTE: ADD package-version-arch-revision_slack${VERSION}                  #
    #       slackware 10.2's changelog says gimp-2.2.12-i486-1                 #
    #       when it's gimp-2.2.12-i486-1_slack10.2 in the ftp                  #
    ############################################################################
    upgrade_package_from_mirror "${UPDATE}"
    case ${?} in
      0)
        # print a message of successful upgrade, also log it if USE_SYSLOG=1.
        if (( ! ${DRY_RUN} ))
        then
	  # NOTE: LOCAL_* variables are not bound at this point.
	  MESSAGE="successfully upgraded package \`${PKG_NAME}' to version ${PKG_VERSION}-${PKG_REV}"
	  # arithmetic - http://www.gnu.org/software/bash/manual/bashref.html#Conditional-Constructs
	  if (( ${USE_SYSLOG} ))
	  then
	    logger -t "${0##*/}" "${FUNCNAME}(): ${MESSAGE}"
	  fi
	  echo "${MESSAGE}" 1>&4
	fi
      ;;
      1)
	echo -e "  ${FUNCNAME}(): ${ERR}error${RST}: couldn't upgrade package \`${HL}${PKG_NAME}${RST}'!" 1>&3
	#if [ "${PKG_LIST_MODE}" = "ChangeLog" ]
	#then
	#  echo -e "  ${HL}tip${RST}: you could try to upgrade with \`${HL}./${SWSP} -u -f ftp${RST}'." 1>&3
	#fi
	echo "failed to upgrade package \`${PKG_NAME}'!" 1>&4
	#FAILED_PACKAGES[${#FAILED_PACKAGES[*]}]="${PKG_NAME}"
	FAILED_PACKAGES+=("${PKG_NAME}")
      ;;
      # FATAL ERROR                                                            #
      ${RET_FERROR})
	echo -e "${ERR}error${RST}: cannot upgrade any packages!" 1>&2
	RET=${RET_FAILED}
	break
      ;;
    esac
  done

  ##############################################################################

  print_upgrade_summary

  return ${RET}
} # security_update()
################################################################################
function read_packages_from_changelog() {
  # 9.8.2009: this function should print a list of the newest version of all   #
  #           available patches                                                #
  #                                                                            #
  # return RET_OK || RET_FAILED                                                #
  #                                                                            #
  # 12.8.2009: TODO: verify ChangeLog                                          #
  #                                                                            #
  # i'm still not happy with this function!!! should we check the ftp only?    #
  # it usually contains only the newest version                                #
  #                                                                            #
  # ...or double check against the ftp?                                        #
  #                                                                            #
  if [ ! -f "${WORK_DIR}/ChangeLog.txt" ]
  then
    echo "${FUNCNAME}(): error: no such file \`${WORK_DIR}/ChangeLog.txt'!" 1>&2
    return ${RET_FAILED}
  fi
  # 9.8.2009: 12.2 ChangeLog: "patches/packages/gnutls-2.6.2-i486-2_slack12.2.tgz"
  #           hence :{0,1} in regexp                                           #
  # 21.8.2009: need to work on this, how do we process                         #
  #            "Tue Aug 18 14:35:23 CDT 2009"                                  #
  #            "patches/packages/linux-2.6.27.31/:"                            #

  awk --re-interval '/^patches\/packages\// {
    match($1, /^patches\/packages\/(.+)-([^-]+-[^-]+-[^-]+)\.t[gx]z:{0,1}.*$/, arr);
    print "'"${FUNCNAME}"'(): DEBUG: "$1" -> "arr[1]" - "arr[2] > "/dev/stderr"
    # we only put the newest (topmost) entry in the array                      #
    if (!(arr[1] in packages)) packages[arr[1]] = arr[2]
  } END {
    for (package in packages) printf "%s-%s\n", package, packages[package]
  }' "${WORK_DIR}/ChangeLog.txt"
  if [ ${?} -ne 0 ]
  then
    echo "${FUNCNAME}(): error: couldn't read packages!" 1>&2
    return ${RET_FAILED}
  fi
  return ${RET_OK}
} # read_packages_from_changelog()
################################################################################
function list_updates() {
  ##############################################################################
  # UNDER CONSTRUCTION!                                                        #
  ##############################################################################
  local -i I=0
  local -i J
  local -i K
  local    PACKAGE
  local    PKG_NAME
  local    AWK_SEARCH
  local -a PACKAGES
  echo "${FUNCNAME}(): please wait..."
  wget -nv --timestamping --directory-prefix="${WORK_DIR}" "${MAIN_MIRROR}/${SLACKWARE}-${VERSION}/ChangeLog.txt"
  [ ${?} -ne 0 ] && {
    echo "${FUNCNAME}(): error: an error occurred at line $[${LINENO}-2] while wgetting the changelog!" 1>&2
    return ${RET_FAILED}
  }
  PACKAGES=(`read_packages_from_changelog`) || return ${RET_FAILED}
  for PACKAGE in ${PACKAGES[*]}
  do
    PKG_NAME="${PACKAGE%-*-*-*}"
    echo -en "  +-[ $((++I)): ${HL}${PKG_NAME}${RST} ]"
    [ ${COLUMNS} -lt 83 ] && K=$[83-${COLUMNS}]
    for ((J=0; J<=$[72-${#I}-${#PKG_NAME}-${K:-0}]; J++))
    do
      echo -n $'-'
    done
    echo -n $'\n'
    ############################################################################
    # REGEXP FRIENDLY                                                          #
    ############################################################################
    AWK_SEARCH=`echo "${PACKAGE}" | sed 's/+/\\\+/g;s/\./\\\./g'`
    awk -v columns="${COLUMNS}" '/patches\/packages\/'"${AWK_SEARCH}"'/ {
      do {
        if(length>columns-4)
        $0 = substr($0, 1, columns-7)"..."
        print "  |",$0
        getline
      } while ($0 !~ /+--------------------------+/ && $0 !~ /patches\/packages\//)
    }' "${WORK_DIR}/ChangeLog.txt" 2>/dev/null
    echo -n $'\n'
  done # | less
  return ${RET_OK}
} # list_updates()
################################################################################
function check_for_updates() {
  ##############################################################################
  # returns RET_OK || RET_FAILED                                               #
  ##############################################################################
  local -a MD5SUMS=(
    `md5sum "${0}" 2>/dev/null | awk '{print $1}'`
    `wget --quiet --output-document=- http://maimed.org/~pyllyukko/files/swsp.sh 2>/dev/null | md5sum | awk '{print $1}'`
  )
  if [ ${#MD5SUMS[*]} -ne 2 -o ${#MD5SUMS[0]} -ne 32 -o ${#MD5SUMS[1]} -ne 32 ]
  then
    echo "${FUNCNAME}(): error at line $[${LINENO}-3]!" 1>&2
    return ${RET_FAILED}
  fi
  [ "x${MD5SUMS[0]}" != "x${MD5SUMS[1]}" ] && echo "versions differ!" || echo "versions match!"
  return ${RET_OK}
} # check_for_updates()
################################################################################
# TODO: ChangeLog is not currently updated!
function print_patch_stats() {
  # print_patch_stats() -- 9.8.2009                                            #
  if [ ! -f "${WORK_DIR}/ChangeLog.txt" ]
  then
    echo "${FUNCNAME}(): error: ChangeLog not available!" 1>&2
    return ${RET_FAILED}
  fi
  local -i COUNT=`grep -c "^patches/packages/" "${WORK_DIR}/ChangeLog.txt"`
  local -a PROGRAMS=(`sed -n 's/^patches\/packages\/\(.\+\)-[^-]\+-[^-]\+-[^-]\+\.t[gx]z:\{0,1\}.*$/\1/p' "${WORK_DIR}/ChangeLog.txt" | sort | uniq`)
  local    PROGRAM
  local -i PATCH_COUNT

  echo "${FUNCNAME}(): warning: ChangeLog might not be up-to-date, so the following data might not be accurate!" 1>&2
  echo "${COUNT} patches:"
  {
    echo "program|patches|percent"
    for PROGRAM in ${PROGRAMS[*]}
    do
      PATCH_COUNT=`grep -c "^patches/packages/${PROGRAM}-[^-]\+-[^-]\+-[^-]\+\.t[gx]z:\{0,1\}.*$" "${WORK_DIR}/ChangeLog.txt"`
      echo "${PROGRAM}|${PATCH_COUNT}|$[${PATCH_COUNT}*100/${COUNT}]%"
    done
  } | column -t -s '|'
  return ${RET_OK}
} # print_patch_stats()
################################################################################
function show_upgrade_history() {
  # this function prints your package upgrade history based on the information
  # available at /var/log/removed_packages.
  local    REMOVED_PACKAGE
  local    PACKAGE
  local    VERSION
  local    TIMESTAMP
  local -a NEW_PACKAGES
  local    NEW_VERSION
  local    GLOB
  # If set, Bash allows filename patterns which match no files to expand to a  #
  # null string, rather than themselves.                                       #
  shopt -s nullglob
  local -a REMOVED_PACKAGES=(/var/log/removed_packages/*-upgraded-*)
  echo $'upgrade history:\n'
  {
    echo 'timestamp|package|old version| |current version'
    for REMOVED_PACKAGE in ${REMOVED_PACKAGES[*]}
    do
      ##########################################################################
      # bash reference manual:                                                 #
      # A `-' may be matched by including it as the first or last character in #
      # the set.                                                               #
      ##########################################################################
      if [[ "${REMOVED_PACKAGE}" =~ "^.+/(.+)-([^-]+)-[^-]+-[^-]+-upgraded-([-0-9,:]+)$" ]]
      then
        #                             pkg- vers--- arch- rev--          timestamp--
        PACKAGE="${BASH_REMATCH[1]}"
        VERSION="${BASH_REMATCH[2]}"
        TIMESTAMP="${BASH_REMATCH[3]}"
        GLOB="/var/log/packages/${PACKAGE}-+([^-])-+([^-])-+([^-])"

        shopt -s extglob
        NEW_PACKAGES=(${GLOB})
        shopt -u extglob
        if [ ${#NEW_PACKAGES[*]} -ne 1 ]
	then
          echo -e "${FUNCNAME}(): ${WRN}warning${RST}: there seems to be more than one package with the same name \`${HL}${PACKAGE}${RST}'!" 1>&2
          continue
	fi
        if [[ "${NEW_PACKAGES[0]}" =~ "^.+/.+-([^-]+)-[^-]+-[^-]+$" ]]
	then
	  NEW_VERSION="${BASH_REMATCH[1]}"
	fi
        echo "${TIMESTAMP}:|${PACKAGE}|${VERSION}|->|${NEW_VERSION}"
      else
        echo -e "${FUNCNAME}(): ${WRN}warning${RST}: error in regular expression or package name \`${REMOVED_PACKAGE##*/}'!" 1>&2
      fi
    done | sort
    shopt -u nullglob
  } | column -t -s '|'
  return ${RET_OK}
} # show_upgrade_history()
################################################################################
function usage() {
  cat <<- EOF
	slackware security patcher
	usage: ${0} [ACTION] [OPTIONS]

	  actions:
	    -a   update SSA cache
	    -d	 dry-run
	    -h	 this help
	    -H   show upgrade history from /var/log/removed_packages
	    -l	 list available updates
	    -p	 print configuration
	    -P	 fetch and import Slackware's PGP key
	    -s   print patch statistics
	    -u	 update
	    -U	 check for swsp updates

	  options:
	    -f m list mode where m = ftp|ChangeLog|FILE_LIST
	         NOTE: FILE_LIST is currently the only supported mode
	    -i   prompt on every package (interactive)
	    -m	 monochrome mode
	    -n   non-verbose mode
	    -S   skip the version comparison tests
	    -x	 debug mode
EOF
  return ${?}
} # usage()
################################################################################
function split_package_name() {
  ##############################################################################
  # $1 = package                                                               #
  # $2 = variable prefix                                                       #
  #                                                                            #
  # returns RET_OK || RET_FAILED                                               #
  ##############################################################################
  # with file extension
  if [[ "${1}" =~ "^(.+)-([^-]+)-([^-]+)-([^-]+)\.(t[gx]z)$" ]]
  then
    eval ${2}_NAME=${BASH_REMATCH[1]}
    eval ${2}_VERSION=${BASH_REMATCH[2]}
    eval ${2}_ARCH=${BASH_REMATCH[3]}
    eval ${2}_REV=${BASH_REMATCH[4]}
    eval ${2}_EXT=${BASH_REMATCH[5]}
  # without file extension
  elif [[ "${1}" =~ "^(.+)-([^-]+)-([^-]+)-([^-]+)$" ]]
  then
    eval ${2}_NAME=${BASH_REMATCH[1]}
    eval ${2}_VERSION=${BASH_REMATCH[2]}
    eval ${2}_ARCH=${BASH_REMATCH[3]}
    eval ${2}_REV=${BASH_REMATCH[4]}
  else
    echo "${FUNCNAME}(): error: invalid package \`${1}'!" 1>&2
    return ${RET_FAILED}
  fi
  return ${RET_OK}
} # split_package_name()
################################################################################
function print_configuration() {
  ##############################################################################
  # this function just prints all kinds of different configurations            #
  ##############################################################################
  echo -e "configuration:"
  echo -e "  Slackware version:\t${HL}${SLACKWARE} ${VERSION}${RST}"
  echo -e "  pid:\t\t\t${HL}$$${RST}"
  echo -e "  working directory:\t${HL}${WORK_DIR}${RST}"
  echo -e "  columns:\t\t${HL}${COLUMNS}${RST}"
  echo -e "  set flags:\t\t${HL}$-${RST}"
  (( ${MONOCHROME} )) && echo -e "  MONOCHROME:\t\t${HL}true${RST}" || echo -e "  MONOCHROME:\t\t${HL}false${RST}"
  (( ${SHOW_DESCRIPTION} )) && echo -e "  SHOW_DESCRIPTION:\t${HL}true${RST}" || echo -e "  SHOW_DESCRIPTION:\t${HL}false${RST}"
  echo -e "  PKG_LIST_MODE:\t${HL}${PKG_LIST_MODE}${RST}"
  echo -e "\nmirrors:"
  for ((I=0; I<${#MIRRORS[*]}; I++))
  do
    echo "  ${MIRRORS[I]}"
  done
  echo -e "\nfunctions:"
  declare -f 2>/dev/null | sed -n '/^.* ().$/s/^/  /p'
  return ${RET_OK}
} # print_configuration()
################################################################################
function sanity_checks() {
  ##############################################################################
  # run few sanity checks to make sure there are no show stoppers              #
  #                                                                            #
  # returns eiher RET_OK or RET_FAILED                                         #
  ##############################################################################
  local FINGERPRINT
  ##############################################################################
  # ARE WE ROOT?                                                               #
  ##############################################################################
  if [ ${UID} -ne 0 -o "x${USER}" != "xroot" ]
  then
    echo "${FUNCNAME}(): error: you must be root to update stuff!" 1>&2
    return ${RET_FAILED}
  fi
  ##############################################################################
  # WORK DIR EXISTS AND IS WRITEABLE?                                          #
  ##############################################################################
  if [ ! -d "${WORK_DIR}" ]
  then
    echo "${FUNCNAME}(): notice: directory \`${WORK_DIR}' does not exist, creating one."
    mkdir -pv "${WORK_DIR}" || {
      echo "${FUNCNAME}(): error: couldn't create/access \`${WORK_DIR}'!" 1>&2
      return ${RET_FAILED}
    }
  fi
  ##############################################################################
  # SLACKWARE VERSION                                                          #
  ##############################################################################
  if [ ! -f /etc/slackware-version ]
  then
    echo "${FUNCNAME}(): error: \`/etc/slackware-version' not found!" 1>&2
    return ${RET_FAILED}
  fi
  if [ -z "${VERSION}" ]
  then
    echo "${FUNCNAME}(): error: error parsing the \`/etc/slackware-version' file!" 1>&2
    return ${RET_FAILED}
  fi
  [[ "${VERSION}" =~ "^[0-9]+\.[0-9]+$" ]] || {
    echo "${FUNCNAME}(): error: couldn't determine Slackware's version!" 1>&2
    return ${RET_FAILED}
  }
  ##############################################################################
  # SLACKWARE'S GPG                                                            #
  # the script executes the same command twice because i wanted to remove all  #
  # ugly hacks relating to the subject                                         #
  ##############################################################################
  gpg \
    --keyring "${GPG_KEYRING}" \
    --no-default-keyring \
    --quiet \
    --fingerprint "Slackware Linux Project <security@slackware.com>" &>/dev/null || {
    # alternative location: http://slackware.com/gpg-key
    echo -e "${FUNCNAME}(): error: you don't have Slackware's public PGP key!" 1>&2
    cat 0<<-EOF 1>&3
	obtain the PGP key by executing the following two commands:
	  wget ftp://ftp.slackware.com/pub/slackware/${SLACKWARE}-${VERSION}/GPG-KEY
	  gpg --keyring \"${GPG_KEYRING}\" --no-default-keyring --import ./GPG-KEY

	or use the -P switch to do this automatically
EOF
    return ${RET_FAILED}
  }
  # compare the fingerprint to the one swsp knows
  FINGERPRINT=`gpg \
    --keyring "${GPG_KEYRING}" \
    --no-default-keyring \
    --fingerprint "Slackware Linux Project <security@slackware.com>" | awk '/Key fingerprint/{sub(/^.+= /, "");print}'`
  if [ "x${PRIMARY_KEY_FINGERPRINT}" != "x${FINGERPRINT}" ]
  then
    echo "${FUNCNAME}(): error: Slackware's primary key fingerprint differs from the one that ${SWSP%\.sh} knows!?!" 1>&2
    return ${RET_FAILED}
  fi
  [[ "${COLUMNS}" =~ "^[0-9]+$" ]] || {
    echo -e "${FUNCNAME}(): ${WRN}warning${RST}: couldn't determine screen width, defaulting to 80!" 1>&2
    COLUMNS=80
  }
  return ${RET_OK}
} # sanity_checks()
################################################################################
function fetch_and_import_PGP_key() {
  wget http://www.slackware.com/gpg-key --output-document=- | gpg --keyring trustedkeys.gpg --no-default-keyring --import -
  return $[ ${PIPESTATUS[0]} | ${PIPESTATUS[1]} ]
} # fetch_and_import_PGP_key()
################################################################################
function print_stack() {
  # this is a debug function that can be called from other functions           #
  local -i I
  echo "${FUNCNAME}(): execution call stack:"
  for ((I=0; I<${#FUNCNAME[*]}; I++))
  do
    echo "  ${I}: ${FUNCNAME[${I}]} called from line ${BASH_LINENO[${I}]}"
  done
  return ${RET_OK}
}
################################################################################
function update_advisories() {
  # this function updates our Slackware security advisory cache from
  # www.slackware.com. (if you know of a better way than the web interface, let
  # me know.)
  local    URL="http://www.slackware.com/security/list.php?l=slackware-security&y=${YEAR}"
  #local -i OLD_COUNT
  local -i NEW_COUNT=0
  local    DATE
  local    ID
  local    PACKAGE
  local    SSA
  local -i WGET_TIMEOUT=10
  local -i WGET_RETRIES=1
  if [ ! -d "${WORK_DIR}/advisories/${YEAR}" ]
  then
    mkdir -pv "${WORK_DIR}/advisories/${YEAR}"
  fi
  echo "${FUNCNAME}(): updating Slackware security advisories..."
  # we define more strict timeouts and retries here, because this function is not THAT important.
  #wget --quiet --connect-timeout=${WGET_TIMEOUT} --tries=${WGET_RETRIES} --output-document=- "${URL}" | sed -n 's/^.\+\([0-9]\{4\}-[0-9]\+-[0-9]\+\).\+\(slackware-security\.[0-9]\+\).\+\s\+\(.\+\)\s\+(\(SSA:[0-9-]\+\).\+$/\1 \2 \3 \4/p' 1>"${WORK_DIR}/advisories/${YEAR}/advisories.txt"
  wget -nv --connect-timeout=${WGET_TIMEOUT} --tries=${WGET_RETRIES} --output-document=- "${URL}" | sed -n 's/^.\+\([0-9]\{4\}-[0-9]\+-[0-9]\+\).\+\(slackware-security\.[0-9]\+\).\+\s\+\(.\+\)\s\+(\(SSA:[0-9-]\+\).\+$/\1 \2 \3 \4/p' 1>"${WORK_DIR}/advisories/${YEAR}/advisories.txt"
  if [ ${?} -ne 0 ]
  then
    echo "${FUNCNAME}(): ${ERR}error${RST}: error occured while downloading advisories." 1>&2
    return ${RET_FAILED}
  fi
  while read DATE ID PACKAGE SSA
  do
    #echo "${DATE} - ${ID} - ${PACKAGE} - ${SSA}"
    #echo "  ${SSA}"
    URL="http://www.slackware.com/security/viewer.php?l=slackware-security&y=${YEAR}&m=${ID}"
    if [ ! -f "${WORK_DIR}/advisories/${YEAR}/${SSA}.txt" -o \
         ! -s "${WORK_DIR}/advisories/${YEAR}/${SSA}.txt" ]
    then
      wget --connect-timeout=${WGET_TIMEOUT} --tries=${WGET_RETRIES} --quiet --output-document=- "${URL}" | \
	awk '/^-----BEGIN PGP SIGNED MESSAGE-----$/,/^-----END PGP SIGNATURE-----$/{print}' 1>"${WORK_DIR}/advisories/${YEAR}/${SSA}.txt"
      ((NEW_COUNT++))
    fi
  done 0<"${WORK_DIR}/advisories/${YEAR}/advisories.txt"

  if [ ${NEW_COUNT} -gt 0 ]
  then
    echo -e "${FUNCNAME}(): ${HL}${NEW_COUNT}${RST} new advisorie(s)" 1>&3
  elif [ ${NEW_COUNT} -eq 0 ]
  then
    echo "${FUNCNAME}(): no new advisories available" 1>&3
  fi

  return ${RET_OK}
} # update_advisories()
################################################################################
[ ${#} -eq 0 ] && {
  usage
  exit ${RET_OK}
}
################################################################################
# output file descriptors:                                                     #
# fd3 = verbose output                                                         #
# fd4 = non-verbose output                                                     #
# fd5 = "real" output (from wget, gpgv, etc.)                                  #
################################################################################
exec 3>&1
exec 4>/dev/null
# print real output of various programs
(( ${PRINT_WGET_OUTPUT} )) && exec 5>&1 || exec 5>/dev/null
################################################################################
# FIRST PROCESS THE PARAMETERS...                                              #
################################################################################
while getopts ":adf:hiHlmnpPsSuUx" OPTION
do
  case "${OPTION}" in
    "a") ACTION="advisories"		;;
    "d") DRY_RUN=1 ACTION="update"	;;
    "f") PKG_LIST_MODE="${OPTARG}"	;;
    "h") ACTION="usage"			;;
    "i") SELECT_UPDATES_INDIVIDUALLY=1	;;
    "H") ACTION="history"		;;
    "l") ACTION="list_updates"		;;
    "m") MONOCHROME=1			;;
    "n")
      # non-verbose mode
      exec 3>/dev/null 4>&1
      MONOCHROME=1 SHOW_DESCRIPTION=0
    ;;
    "p") ACTION="print_config"	;;
    "P")
      # this needs to be done before the sanity_checks()
      fetch_and_import_PGP_key
      exit ${RET_OK}
    ;;
    "s") ACTION="print_stats"	;;
    "S") SKIP_VERSION_TEST=1	;;
    "u") ACTION="update"	;;
    "U") ACTION="check_updates"	;;
    "x") set -x			;;
    *)
      echo -e "${ERR}error${RST}: illegal option -- ${OPTARG}" 1>&2
      exit ${RET_FAILED}
    ;;
  esac
done
if (( ${MONOCHROME} ))
then
  declare -r HL=""
  declare -r RST=""
  declare -r ERR=""
  declare -r WRN=""
  declare -r SCP=""
  declare -r RCP=""
else
  declare -r HL="\033[1m"
  declare -r RST="\033[0m"
  declare -r ERR="\033[0;31m"
  declare -r WRN="\033[1;31m"
  declare -r SCP="\033[s"
  declare -r RCP="\033[u"
fi
sanity_checks || exit ${RET_FAILED}
################################################################################
# ...THEN DECIDE WHAT TO DO!                                                   #
################################################################################
case "${ACTION}" in
  "advisories")    update_advisories          ;;
  "check_updates") check_for_updates          ;;
  "history")       show_upgrade_history       ;;
  "list_updates")  list_updates               ;;
  "print_config")  print_configuration | more ;;
  "print_stats")   print_patch_stats          ;;
  "update")        security_update            ;;
  "usage")
    usage
    exit ${RET_OK}
  ;;
esac
# if swsp detected kernel updates amongst the upgraded packages,               #
# a little reminder.                                                           #
if (( ${KERNEL_UPGRADE} ))
then
  echo -e "\n${HL}notice${RST}: kernel updates"
  [ -n "${KERNEL_UPGRADE_README}" ] && echo "        there seems to be a README available at ${KERNEL_UPGRADE_README}, i suggest you read it."
  echo -n $'\n'
fi
################################################################################
# and then for some totally unnecessary information!-)                         #
################################################################################
echo -e "\nscript finished in ${HL}${SECONDS}${RST} second(s)."
exit ${RET_OK}
