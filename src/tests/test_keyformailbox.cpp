/*
    test_keyformailbox.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
*/

#include <qgpgme/protocol.h>
#include <qgpgme/keyformailboxjob.h>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <QDebug>


int main(int argc, char **argv)
{
    QString mailbox;
    if (argc == 2) {
        mailbox = QString::fromLocal8Bit(argv[1]);
    }

    const auto proto = QGpgME::openpgp();
    auto *job = proto->keyForMailboxJob();
    GpgME::Key k;
    GpgME::UserID uid;
    job->exec(mailbox, true, k, uid);
    qDebug() << "UID Name: " << uid.name() << " Mail: " << uid.email() << " id: " << uid.id();
    qDebug() << "Key fpr: " << k.primaryFingerprint();
    return 0;
}
