/*
    test_keygen.cpp

    This file is part of libkleopatra's test suite.
    Copyright (c) 2004 Klarälvdalens Datakonsult AB

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

#include "test_keygen.h"

#include <qgpgme/keylistjob.h>
#include <qgpgme/keygenerationjob.h>
#include <qgpgme/protocol.h>
#include "ui/progressdialog.h"

#include <gpgme++/keygenerationresult.h>

#include <KAboutData>

#include <kmessagebox.h>
#include <QDebug>

#include <QLineEdit>
#include <QLabel>
#include <QGridLayout>

#include <QApplication>
#include <KLocalizedString>
#include <QCommandLineParser>
#include <QDialogButtonBox>
#include <QPushButton>
#include <KGuiItem>
#include <QVBoxLayout>

static const char *const keyParams[] = {
    "Key-Type", "Key-Length",
    "Subkey-Type", "Subkey-Length",
    "Name-Real", "Name-Comment", "Name-Email", "Name-DN",
    "Expire-Date",
    "Passphrase"
};
static const int numKeyParams = sizeof keyParams / sizeof * keyParams;

static const char *protocol = nullptr;

KeyGenerator::KeyGenerator(QWidget *parent)
    : QDialog(parent)
{
    setModal(true);
    setWindowTitle(QStringLiteral("KeyGenerationJob test"));
    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close);
    QWidget *mainWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(mainWidget);
    QPushButton *user1Button = new QPushButton;
    buttonBox->addButton(user1Button, QDialogButtonBox::ActionRole);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &KeyGenerator::reject);
    user1Button->setDefault(true);
    KGuiItem::assign(user1Button, KGuiItem(QStringLiteral("Create")));

    QWidget *w = new QWidget(this);
    mainLayout->addWidget(w);
    mainLayout->addWidget(buttonBox);

    QGridLayout *glay = new QGridLayout(w);

    int row = -1;

    ++row;
    glay->addWidget(new QLabel(QStringLiteral("<GnupgKeyParms format=\"internal\">"), w),
                    row, 0, 1, 2);
    for (int i = 0; i < numKeyParams; ++i) {
        ++row;
        glay->addWidget(new QLabel(QString::fromLatin1(keyParams[i]), w), row, 0);
        glay->addWidget(mLineEdits[i] = new QLineEdit(w), row, 1);
    }

    ++row;
    glay->addWidget(new QLabel(QStringLiteral("</GnupgKeyParms>"), w), row, 0, 1, 2);
    ++row;
    glay->setRowStretch(row, 1);
    glay->setColumnStretch(1, 1);

    connect(user1Button, &QPushButton::clicked, this, &KeyGenerator::slotStartKeyGeneration);
}

KeyGenerator::~KeyGenerator() {}

void KeyGenerator::slotStartKeyGeneration()
{
    QString params = QStringLiteral("<GnupgKeyParms format=\"internal\">\n");
    for (int i = 0; i < numKeyParams; ++i)
        if (mLineEdits[i] && !mLineEdits[i]->text().trimmed().isEmpty()) {
            params += QString::fromLatin1(keyParams[i]) + (QStringLiteral(": ") + mLineEdits[i]->text().trimmed()) + QLatin1Char('\n');
        }
    params += QStringLiteral("</GnupgKeyParms>\n");

    const QGpgME::Protocol *proto = nullptr;
    if (protocol) {
        proto = !strcmp(protocol, "openpgp") ? QGpgME::openpgp() : QGpgME::smime();
    }
    if (!proto) {
        proto = QGpgME::smime();
    }
    Q_ASSERT(proto);

    qDebug() << "Using protocol" << proto->name();

    QGpgME::KeyGenerationJob *job = proto->keyGenerationJob();
    Q_ASSERT(job);

    connect(job, &QGpgME::KeyGenerationJob::result, this, &KeyGenerator::slotResult);

    const GpgME::Error err = job->start(params);
    if (err) {
        showError(err);
    }
#ifndef LIBKLEO_NO_PROGRESSDIALOG
    else {
        (void)new Kleo::ProgressDialog(job, QStringLiteral("Generating key"), this);
    }
#endif
}

void KeyGenerator::showError(const GpgME::Error &err)
{
    KMessageBox::error(this, QStringLiteral("Could not start key generation: %1").arg(QString::fromLocal8Bit(err.asString())),
                       QStringLiteral("Key Generation Error"));
}

void KeyGenerator::slotResult(const GpgME::KeyGenerationResult &res, const QByteArray &keyData)
{
    if (res.error()) {
        showError(res.error());
    } else
        KMessageBox::information(this, QStringLiteral("Key generated successfully, %1 bytes long").arg(keyData.size()),
                                 QStringLiteral("Key Generation Finished"));
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        protocol = argv[1];
        argc = 1; // hide from KDE
    }
    QApplication app(argc, argv);
    KAboutData aboutData(QStringLiteral("test_keygen"), i18n("KeyGenerationJob Test"), QStringLiteral("0.1"));
    QCommandLineParser parser;
    KAboutData::setApplicationData(aboutData);
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    KeyGenerator *keygen = new KeyGenerator(nullptr);
    keygen->setObjectName(QStringLiteral("KeyGenerator top-level"));
    keygen->show();

    return app.exec();
}

