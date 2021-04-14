/*
    test_keyresolver.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
*/


#include "kleo/keyresolver.h"

#include "utils/formatting.h"

#include <QCommandLineParser>
#include <QApplication>
#include <QDebug>
#include <QTimer>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace GpgME;

void dumpKeys(const QMap<QString, std::vector<Key>> &keysMap)
{
    for (auto it = std::begin(keysMap); it != std::end(keysMap); ++it) {
        const auto &address = it.key();
        const auto &keys = it.value();
        qDebug() << "Address:" << address;
        qDebug() << "Keys:";
        for (const auto &key: keys) {
            qDebug() << key.primaryFingerprint();
        }
    }
}

void dumpSigKeys(const std::vector<Key> &keys)
{
    for (const auto &key: keys) {
        qDebug() << key.primaryFingerprint();
    }
}

class SignalRecipient: public QObject
{
    Q_OBJECT
public:
    SignalRecipient(KeyResolver *res) : resolver(res) {}

    void keysResolved(bool success, bool sendUnencrypted)
    {
        if (!success) {
            qDebug() << "Canceled";
            exit(1);
        }
        const auto result = resolver->result();
        qDebug() << "Resolved Signing keys:";
        dumpSigKeys(result.signingKeys);
        qDebug() << "Resolved Encryption keys:";
        dumpKeys(result.encryptionKeys);
        qDebug() << "Send Unencrypted:" << sendUnencrypted;
        exit(0);
    }
private:
    KeyResolver *resolver;
};

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Test KeyResolver class"));
    parser.addHelpOption();
    parser.addPositionalArgument(QStringLiteral("recipients"),
                                  QStringLiteral("Recipients to resolve"),
                                  QStringLiteral("[mailboxes]"));
    parser.addOption(QCommandLineOption({QStringLiteral("overrides"), QStringLiteral("o")},
                                        QStringLiteral("Override where format can be:\n"
                                                       "OpenPGP\n"
                                                       "SMIME\n"
                                                       "Auto"),
                                        QStringLiteral("mailbox:fpr,fpr,...[:format]")));
    parser.addOption(QCommandLineOption({QStringLiteral("sender"), QStringLiteral("s")},
                                        QStringLiteral("Mailbox of the sender"),
                                        QStringLiteral("mailbox")));
    parser.addOption(QCommandLineOption({QStringLiteral("sigkeys"), QStringLiteral("k")},
                                        QStringLiteral("Explicit signing keys"),
                                        QStringLiteral("signing key")));
    parser.addOption(QCommandLineOption({QStringLiteral("encrypt"), QStringLiteral("e")},
                                        QStringLiteral("Only select encryption keys")));
    parser.addOption(QCommandLineOption({QStringLiteral("approval"), QStringLiteral("a")},
                                        QStringLiteral("Always show approval dlg")));

    parser.process(app);

    const QStringList recps = parser.positionalArguments();
    if (recps.size() < 1) {
        parser.showHelp(1);
    }

    KeyResolver resolver(true, !parser.isSet(QStringLiteral("encrypt")));
    resolver.setRecipients(recps);
    resolver.setSender(parser.value(QStringLiteral("sender")));

    QMap <Protocol, QMap <QString, QStringList> > overrides;

    for (const QString &oride: parser.values(QStringLiteral("overrides"))) {
        const QStringList split = oride.split(QLatin1Char(':'));
        Protocol fmt = UnknownProtocol;
        if (split.size() < 2 || split.size() > 3) {
            parser.showHelp(1);
        }

        if (split.size() == 3) {
            const QString fmtStr = split[2].toLower();
            if (fmtStr == QLatin1String("openpgp")) {
                fmt = OpenPGP;
            } else if (fmtStr == QLatin1String("smime")) {
                fmt = CMS;
            } else if (fmtStr == QLatin1String("auto")) {
                fmt = UnknownProtocol;
            } else {
                parser.showHelp(1);
            }
        }
        const QStringList fingerprints = split[1].split(QLatin1Char(','));

        auto map = overrides.value(fmt);
        map.insert(split[0], fingerprints);
        overrides.insert(fmt, map);
    }
    resolver.setOverrideKeys(overrides);

    auto recp = new SignalRecipient(&resolver);
    QObject::connect (&resolver, &KeyResolver::keysResolved, recp, &SignalRecipient::keysResolved);

    QTimer::singleShot(1000, [&parser, &resolver]() {
        resolver.start(parser.isSet(QStringLiteral("approval")));
    });

    app.exec();
    return 0;
}

#include "test_keyresolver.moc"
