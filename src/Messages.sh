#! /bin/sh
$EXTRACTRC */*.ui >> rc.cpp || exit 11
$XGETTEXT `find . -name \*.cc -o -name \*.cpp -o -name \*.h | grep -v '/tests/' | grep -v '/autotests/'` -o $podir/libkleopatra.pot
rm -f rc.cpp
