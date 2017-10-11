/*
    test_auditlog.cpp

    This file is part of libkleopatra's test suite.
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

const char * auditlog =
"<div class=\"GnuPGAuditLog\">"
"<table border=\"0\">"
"  <colgroup>"
"    <col width=\"80%\" />"
"    <col width=\"20%\" />"
"   </colgroup>"
"  <tr><td><table><tr><td><font color=\"green\">*</font></td><td>Data verification succeeded</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;</td><td>Data available</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;</td><td>Signature available</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;</td><td>Parsing data succeeded</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (data hash algorithm: SHA1)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;</td><td>Signature 0</td></tr></table></td><td><font color=\"green\">Good</font></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#0B/CN=Email CA 2013,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (data hash algorithm: SHA1)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (attr hash algorithm: SHA1)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;&nbsp;&nbsp;</td><td>Certificate chain available</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#00/CN=Root CA 2010,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#04/CN=Root CA 2010,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/CN=Email CA 2013,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;ca@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/(3:uri24:http://ca.intevation.org))</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#0B/CN=Email CA 2013,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/CN=Andre Heinecke,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;andre.heinecke@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;aheinecke@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;andre@heinecke.or.at>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;&nbsp;&nbsp;</td><td>Certificate chain valid</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font>&nbsp;&nbsp;&nbsp;&nbsp;</td><td>Root certificate trustworthy</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;</td><td>CRL/OCSP check of certificates</td></tr></table></td><td>Not enabled</td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;</td><td>Included certificates</td></tr></table></td><td>2</td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#0B/CN=Email CA 2013,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/CN=Andre Heinecke,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;andre.heinecke@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;aheinecke@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;andre@heinecke.or.at>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (#04/CN=Root CA 2010,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/CN=Email CA 2013,O=Intevation GmbH,C=DE)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/&lt;ca@intevation.de>)</td></tr></table></td></tr>"
"  <tr><td><table><tr><td>*&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td><td> (/(3:uri24:http://ca.intevation.org))</td></tr></table></td></tr>"
"  <tr><td><table><tr><td><font color=\"green\">*</font></td><td>Gpg-Agent usable</td></tr></table></td><td><font color=\"green\">Yes</font></td></tr>"
"</table>"
"</div>";

#include "libkleo/messagebox.h"

#include <KAboutData>


#include <QApplication>
#include <KLocalizedString>
#include <QCommandLineParser>

int main(int argc, char **argv)
{

    QApplication app(argc, argv);
    KAboutData aboutData(QStringLiteral("test_auditlog"), i18n("Auditlog Test"), QStringLiteral("0.1"));
    QCommandLineParser parser;
    KAboutData::setApplicationData(aboutData);
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    Kleo::MessageBox::auditLog(nullptr, QString::fromLatin1(auditlog), QStringLiteral("Test"));

    return app.exec();
}

