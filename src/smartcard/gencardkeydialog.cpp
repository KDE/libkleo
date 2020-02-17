/*  dialogs/gencardkeydialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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

#include "gencardkeydialog.h"

#include <QDialogButtonBox>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>

#include <KEMailSettings>
#include <KEmailAddress>
#include <KLocalizedString>

using namespace Kleo;

class GenCardKeyDialog::Private
{
public:
    Private(GenCardKeyDialog *qq): q(qq)
    {
        auto *vBox = new QVBoxLayout(q);
        auto *grid = new QGridLayout;
        vBox->addLayout(grid);

        auto bbox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, qq);

        mOkButton = bbox->button(QDialogButtonBox::Ok);

        mOkButton->setDefault(true);
        mOkButton->setShortcut(Qt::CTRL | Qt::Key_Return);
        connect(bbox, &QDialogButtonBox::rejected, q, [this]() {q->reject();});
        connect(bbox, &QDialogButtonBox::accepted, q, [this]() {accept();});

        vBox->addWidget(bbox);

        const KEMailSettings e;
        mNameEdit = new QLineEdit(e.getSetting(KEMailSettings::RealName));
        mEmailEdit = new QLineEdit(e.getSetting(KEMailSettings::EmailAddress));

        connect(mEmailEdit, &QLineEdit::textChanged, q, [this]() {checkAcceptable();});

        auto nameLabel = new QLabel(i18n("Name:"));
        auto mailLabel = new QLabel(i18n("EMail:"));
        mInvalidEmailLabel = new QLabel(QStringLiteral("<font size='small'>%1</font>").arg(
            i18n("Invalid EMail")));
        int row = 0;
        grid->addWidget(nameLabel, row, 0);
        grid->addWidget(mNameEdit, row++, 1);
        grid->addWidget(mailLabel, row, 0);
        grid->addWidget(mEmailEdit, row++, 1);
        grid->addWidget(mInvalidEmailLabel, row++, 1);

        // In the future GnuPG may support more algos but for now
        // (2.1.18) we are stuck with RSA for on card generation.
        auto rsaLabel = new QLabel(i18n("RSA Keysize:"));
        mKeySizeCombo = new QComboBox;

        grid->addWidget(rsaLabel, row, 0);
        grid->addWidget(mKeySizeCombo, row++, 1);

        mBackupCheckBox = new QCheckBox(i18n("Backup encryption key"));
        mBackupCheckBox->setToolTip(i18n("Backup the encryption key in a file.") + QStringLiteral("<br/>") +
                                    i18n("You will be asked for a passphrase to protect that file during key generation."));

        mBackupCheckBox->setChecked(true);

        grid->addWidget(mBackupCheckBox, row++, 0, 1, 2);

        q->setMinimumWidth(400);

        checkAcceptable();
    }

    void accept()
    {
        params.name = mNameEdit->text();
        params.email = mEmailEdit->text();
        params.keysize = mKeySizeCombo->currentText().toInt();
        params.algo = GpgME::Subkey::AlgoRSA;
        params.backup = mBackupCheckBox->isChecked();
        q->accept();
    }

    void setSupportedSizes(const std::vector<int> &sizes)
    {
        mKeySizeCombo->clear();
        for (auto size: sizes) {
            mKeySizeCombo->addItem(QString::number(size));
        }
        mKeySizeCombo->setCurrentIndex(mKeySizeCombo->findText(QStringLiteral("2048")));
    }

    void checkAcceptable()
    {
        // We only require a valid mail address
        const QString mail = mEmailEdit->text();
        if (!mail.isEmpty() &&
            KEmailAddress::isValidSimpleAddress(mail)) {
            mOkButton->setEnabled(true);
            mInvalidEmailLabel->hide();
            return;
        }
        if (!mail.isEmpty()) {
            mInvalidEmailLabel->show();
        } else {
            mInvalidEmailLabel->hide();
        }
        mOkButton->setEnabled(false);
    }

    GenCardKeyDialog *q;
    KeyParams params;
    QPushButton *mOkButton;
    QLineEdit *mNameEdit;
    QLineEdit *mEmailEdit;
    QLabel *mInvalidEmailLabel;
    QComboBox *mKeySizeCombo;
    QCheckBox *mBackupCheckBox;
};

GenCardKeyDialog::GenCardKeyDialog(QWidget *parent) : QDialog(parent),
    d(new Private(this))
{
}

void GenCardKeyDialog::setSupportedSizes(const std::vector<int> &sizes)
{
    d->setSupportedSizes(sizes);
}

GenCardKeyDialog::KeyParams GenCardKeyDialog::getKeyParams() const
{
    return d->params;
}
