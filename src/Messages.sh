#! /bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: none
$EXTRACTRC */*.ui >> rc.cpp || exit 11
$XGETTEXT `find . -name \*.cc -o -name \*.cpp -o -name \*.h | grep -v '/tests/' | grep -v '/autotests/'` -o $podir/libkleopatra6.pot
rm -f rc.cpp
