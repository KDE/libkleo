/*
    test_jobs.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#include <qgpgme/protocol.h>
#include <qgpgme/signjob.h>
#include <qgpgme/keylistjob.h>

#include <gpgme++/key.h>
#include <gpgme++/signingresult.h>
#include <gpgme++/keylistresult.h>

#include <QDebug>
#include <KAboutData>

#include <memory>
#include <QApplication>
#include <KLocalizedString>
#include <QCommandLineParser>

static const char *protocol = nullptr;

static void testSign()
{
    const QGpgME::Protocol *proto = !strcmp(protocol, "openpgp") ? QGpgME::openpgp() : QGpgME::smime();
    Q_ASSERT(proto);

    qDebug() << "Using protocol" << proto->name();

    std::vector<GpgME::Key> signingKeys;

    std::unique_ptr<QGpgME::KeyListJob> listJob(proto->keyListJob(false, false, true));     // use validating keylisting
    if (listJob.get()) {
        // ##### Adjust this to your own identity
        listJob->exec(QStringList(QStringLiteral("kloecker@kde.org")), true /*secret*/, signingKeys);
        Q_ASSERT(!signingKeys.empty());
    } else {
        Q_ASSERT(0);   // job failed
    }

    QGpgME::SignJob *job = proto->signJob(true, true);

    QByteArray plainText = "Hallo Leute\n"; // like gpgme's t-sign.c
    qDebug() << "plainText=" << plainText;

    qDebug() << " signing with" << signingKeys[0].primaryFingerprint();

    QByteArray signature;
    const GpgME::SigningResult res =
        job->exec(signingKeys, plainText, GpgME::Clearsigned, signature);
    if (res.error().isCanceled()) {
        qDebug() << "signing was canceled by user";
        return;
    }
    if (res.error()) {
        qDebug() << "signing failed:" << res.error().asString();
        return;
    }
    qDebug() << "signing resulted in signature="
             << signature;
}

int main(int argc, char **argv)
{
    protocol = "openpgp";
    if (argc == 2) {
        protocol = argv[1];
        argc = 1; // hide from KDE
    }
    QApplication app(argc, argv);
    KAboutData aboutData(QStringLiteral("test_jobs"), i18n("Signing Job Test"), QStringLiteral("0.1"));
    QCommandLineParser parser;
    KAboutData::setApplicationData(aboutData);
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    testSign();
}
