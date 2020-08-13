/*
    test_auditlog.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
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

