/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#include "ui/keyselectioncombo.h"
#include "kleo/defaultkeyfilter.h"
#include <gpgme++/key.h>

#include <KAboutData>
#include <QDebug>

#include <vector>
#include <QApplication>
#include <KLocalizedString>
#include <QCommandLineParser>
#include <QVBoxLayout>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    KAboutData aboutData(QStringLiteral("test_keyselectioncombo"), i18n("KeySelectionCombo Test"), QStringLiteral("0.1"));
    QCommandLineParser parser;
    QCommandLineOption openpgpOption(QStringLiteral("openpgp"), i18n("Show OpenPGP keys"));
    parser.addOption(openpgpOption);
    QCommandLineOption smimeOption(QStringLiteral("smime"), i18n("Show S/MIME keys"));
    parser.addOption(smimeOption);
    QCommandLineOption encryptOption(QStringLiteral("encryption"), i18n("Show keys for encryption"));
    parser.addOption(encryptOption);
    QCommandLineOption signingOption(QStringLiteral("signing"), i18n("Show keys for signing"));
    parser.addOption(signingOption);

    KAboutData::setApplicationData(aboutData);
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    QWidget window;
    QVBoxLayout layout(&window);

    Kleo::KeySelectionCombo combo;
    layout.addWidget(&combo);

    std::shared_ptr<const Kleo::DefaultKeyFilter> filter(new Kleo::DefaultKeyFilter);
    filter->setCanSign(parser.isSet(signingOption) ? Kleo::DefaultKeyFilter::Set : Kleo::DefaultKeyFilter::DoesNotMatter);
    filter->setCanEncrypt(parser.isSet(encryptOption) ? Kleo::DefaultKeyFilter::Set : Kleo::DefaultKeyFilter::DoesNotMatter);
    filter->setIsOpenPGP(parser.isSet(openpgpOption) ? Kleo::DefaultKeyFilter::Set : Kleo::DefaultKeyFilter::NotSet);
    filter->setHasSecret(Kleo::DefaultKeyFilter::Set);
    //filter->setOwnerTrust(Kleo::DefaultKeyFilter::IsAtLeast);
    //filter->setOwnerTrustReferenceLevel(GpgME::Key::Ultimate);
    combo.setKeyFilter(filter);

    combo.prependCustomItem(QIcon(), i18n("No key"), QStringLiteral("no-key"));
    QObject::connect(&combo, &Kleo::KeySelectionCombo::currentKeyChanged, [](const GpgME::Key &key) { qDebug() << "Current key changed:" << key.keyID(); });
    QObject::connect(&combo, &Kleo::KeySelectionCombo::customItemSelected, [](const QVariant &data) { qDebug() << "Custom item selected:" << data.toString(); });

    window.show();

    /*
    if (dlg.exec() == QDialog::Accepted) {
        qDebug() << "accepted; selected key:" << (dlg.selectedKey().userID(0).id() ? dlg.selectedKey().userID(0).id() : "<null>") << "\nselected _keys_:";
        for (std::vector<GpgME::Key>::const_iterator it = dlg.selectedKeys().begin(); it != dlg.selectedKeys().end(); ++it) {
            qDebug() << (it->userID(0).id() ? it->userID(0).id() : "<null>");
        }
    } else {
        qDebug() << "rejected";
    }
    */

    return app.exec();
}

