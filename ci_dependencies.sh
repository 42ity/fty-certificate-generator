#!/usr/bin/env bash

################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  READ THE ZPROJECT/README.MD FOR INFORMATION ABOUT MAKING PERMANENT CHANGES. #
################################################################################

REQUESTED_BRANCH=$1

set -e

if [ -z "$DEPENDENCIES_DIR" ]; then
    export DEPENDENCIES_DIR="`pwd`/tmp-deps"
fi
mkdir -p "$DEPENDENCIES_DIR"
cd "$DEPENDENCIES_DIR"

# Clone and build dependencies, if not yet installed to Travis env as DEBs
# or MacOS packages; other OSes are not currently supported by Travis cloud
echo "`date`: Starting build of dependencies (if any) using ci_dependencies.sh $REQUESTED_BRANCH..."

# Start of recipe for dependency: log4cplus
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list log4cplus-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions log4cplus >/dev/null 2>&1) || \
       ([ -e "log4cplus" ]) \
; then
FOLDER_NAME="log4cplus-1.1.2-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'log4cplus' from Git repository..." >&2
    echo "git clone -b 1.1.2-FTY-master https://github.com/42ity/log4cplus.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b 1.1.2-FTY-master https://github.com/42ity/log4cplus.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'log4cplus' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: fty-common-logging
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_common_logging-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-common-logging >/dev/null 2>&1) || \
       ([ -e "fty-common-logging" ]) \
; then
FOLDER_NAME="fty-common-logging-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'fty-common-logging' from Git repository..." >&2
    echo "git clone -b master https://github.com/42ity/fty-common-logging.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-common-logging.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'fty-common-logging' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: cxxtools
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list cxxtools-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions cxxtools >/dev/null 2>&1) || \
       ([ -e "cxxtools" ]) \
; then
FOLDER_NAME="cxxtools-2.2-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'cxxtools' from Git repository..." >&2
    echo "git clone -b 2.2-FTY-master https://github.com/42ity/cxxtools.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b 2.2-FTY-master https://github.com/42ity/cxxtools.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'cxxtools' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: fty-common
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_common-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-common >/dev/null 2>&1) || \
       ([ -e "fty-common" ]) \
; then
FOLDER_NAME="fty-common-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'fty-common' from Git repository..." >&2
    echo "git clone -b master https://github.com/42ity/fty-common.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-common.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'fty-common' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: openssl
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libssl-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions openssl >/dev/null 2>&1) || \
       ([ -e "openssl" ]) \
; then
    echo ""
    echo "WARNING: Can not build prerequisite 'openssl'" >&2
    echo "because neither tarball nor repository sources are known for it," >&2
    echo "and it was not installed as a package; this may cause the test to fail!" >&2
fi

# Start of recipe for dependency: fty-lib-certificate
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_lib_certificate-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-lib-certificate >/dev/null 2>&1) || \
       ([ -e "fty-lib-certificate" ]) \
; then
FOLDER_NAME="fty-lib-certificate-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'fty-lib-certificate' from Git repository..." >&2
    echo "git clone -b master https://github.com/42ity/fty-lib-certificate.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-lib-certificate.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'fty-lib-certificate' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: libsodium
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1) || \
       ([ -e "libsodium" ]) \
; then
FOLDER_NAME="libsodium-1.0.5-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'libsodium' from Git repository..." >&2
    echo "git clone -b 1.0.5-FTY-master https://github.com/42ity/libsodium.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b 1.0.5-FTY-master https://github.com/42ity/libsodium.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'libsodium' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: libzmq
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libzmq3-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions libzmq >/dev/null 2>&1) || \
       ([ -e "libzmq" ]) \
; then
FOLDER_NAME="libzmq-4.2.0-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'libzmq' from Git repository..." >&2
    echo "git clone -b 4.2.0-FTY-master https://github.com/42ity/libzmq.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b 4.2.0-FTY-master https://github.com/42ity/libzmq.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'libzmq' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: czmq
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libczmq-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions czmq >/dev/null 2>&1) || \
       ([ -e "czmq" ]) \
; then
FOLDER_NAME="czmq-v3.0.2-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'czmq' from Git repository..." >&2
    echo "git clone -b v3.0.2-FTY-master https://github.com/42ity/czmq.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b v3.0.2-FTY-master https://github.com/42ity/czmq.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'czmq' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: malamute
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libmlm-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions malamute >/dev/null 2>&1) || \
       ([ -e "malamute" ]) \
; then
FOLDER_NAME="malamute-1.0-fty-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'malamute' from Git repository..." >&2
    echo "git clone -b 1.0-FTY-master https://github.com/42ity/malamute.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b 1.0-FTY-master https://github.com/42ity/malamute.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'malamute' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: fty-common-mlm
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_common_mlm-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-common-mlm >/dev/null 2>&1) || \
       ([ -e "fty-common-mlm" ]) \
; then
FOLDER_NAME="fty-common-mlm-master"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'fty-common-mlm' from Git repository..." >&2
    echo "git clone -b master https://github.com/42ity/fty-common-mlm.git $FOLDER_NAME"
    $CI_TIME git clone --quiet --depth 1 -b master https://github.com/42ity/fty-common-mlm.git $FOLDER_NAME
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'fty-common-mlm' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

# Start of recipe for dependency: fty-security-wallet
if ! (command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libfty_security_wallet-dev >/dev/null 2>&1) || \
       (command -v brew >/dev/null 2>&1 && brew ls --versions fty-security-wallet >/dev/null 2>&1) || \
       ([ -e "fty-security-wallet" ]) \
; then
FOLDER_NAME="fty-security-wallet"

if [ -d "$FOLDER_NAME" ]
    echo "$FOLDER_NAME already exist. Skipped." >&2
then
    echo ""
    BASE_PWD=${PWD}
    echo "`date`: INFO: Building prerequisite 'fty-security-wallet' from Git repository..." >&2
    if [ "x$REQUESTED_BRANCH" = "x" ]; then
        echo "git clone -b https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME"
        $CI_TIME git clone --quiet --depth 1 https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME
    else
        if git ls-remote --heads https://github.com/perrettecl/fty-security-wallet.git | grep -q "$REQUESTED_BRANCH"; then
            echo "git clone -b "$REQUESTED_BRANCH" https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME"
            $CI_TIME git clone --quiet --depth 1 -b "$REQUESTED_BRANCH" https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME
        else
            echo "$REQUESTED_BRANCH not found for https://github.com/perrettecl/fty-security-wallet.git"
            echo "git clone -b https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME"
            $CI_TIME git clone --quiet --depth 1 https://github.com/perrettecl/fty-security-wallet.git $FOLDER_NAME
        fi
    fi
    cd "./$FOLDER_NAME"
    CCACHE_BASEDIR=${PWD}
    export CCACHE_BASEDIR
        git --no-pager log --oneline -n1
    if [ -e ci_dependencies.sh ]; then
        PROPAGATED_BRANCH="`git branch | grep * | cut -d ' ' -f2`"
        echo "`date`: INFO: Building prerequisites of 'fty-security-wallet' using ci_dependencies.sh $PROPAGATED_BRANCH..." >&2
        ($CI_TIME source ./ci_dependencies.sh $PROPAGATED_BRANCH)
    fi
    if [ -e autogen.sh ]; then
        $CI_TIME ./autogen.sh 2> /dev/null
    fi
    if [ -e buildconf ]; then
        $CI_TIME ./buildconf 2> /dev/null
    fi
    if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ]; then
        $CI_TIME libtoolize --copy --force && \
        $CI_TIME aclocal -I . && \
        $CI_TIME autoheader && \
        $CI_TIME automake --add-missing --copy && \
        $CI_TIME autoconf || \
        $CI_TIME autoreconf -fiv
    fi
    $CI_TIME ./configure "${CONFIG_OPTS[@]}"
    $CI_TIME make -j4
    $CI_TIME make install
    cd "${BASE_PWD}"
fi
fi

