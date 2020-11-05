/*
    test_keygen.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#include "ui/keyselectiondialog.h"
#include <gpgme++/key.h>

#include <KAboutData>
#include <QDebug>

#include <vector>
#include <QApplication>
#include <KLocalizedString>
#include <QCommandLineParser>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    KAboutData aboutData(QStringLiteral("test_keyselectiondialog"), i18n("KeySelectionDialog Test"), QStringLiteral("0.1"));
    QCommandLineParser parser;
    KAboutData::setApplicationData(aboutData);
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    Kleo::KeySelectionDialog dlg(QStringLiteral("Kleo::KeySelectionDialog Test"),
                                 QStringLiteral("Please select a key:"),
                                 std::vector<GpgME::Key>(),
                                 Kleo::KeySelectionDialog::AllKeys, true, true);

    if (dlg.exec() == QDialog::Accepted) {
        qDebug() << "accepted; selected key:" << (dlg.selectedKey().userID(0).id() ? dlg.selectedKey().userID(0).id() : "<null>") << "\nselected _keys_:";
        for (auto it = dlg.selectedKeys().begin(); it != dlg.selectedKeys().end(); ++it) {
            qDebug() << (it->userID(0).id() ? it->userID(0).id() : "<null>");
        }
    } else {
        qDebug() << "rejected";
    }

    return 0;
}
