/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Libkleo.
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "openpgpcertificatecreationdialog.h"

#include "animatedexpander.h"
#include "nameandemailwidget.h"
#include "openpgpcertificatecreationconfig.h"
#include "utils/compat.h"
#include "utils/compliance.h"
#include "utils/expiration.h"
#include "utils/gnupg.h"
#include "utils/keyparameters.h"
#include "utils/keyusage.h"

#include <KAdjustingScrollArea>
#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>
#include <KSharedConfig>

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace Qt::Literals::StringLiterals;

static bool unlimitedValidityIsAllowed()
{
    return !Kleo::Expiration::maximumExpirationDate().isValid();
}

class OpenPGPCertificateCreationDialog::Private
{
    friend class ::Kleo::OpenPGPCertificateCreationDialog;
    OpenPGPCertificateCreationDialog *const q;

    struct UI {
        QLabel *infoLabel;
        KAdjustingScrollArea *scrollArea;
        NameAndEmailWidget *nameAndEmail;
        QCheckBox *withPassCheckBox;
        QDialogButtonBox *buttonBox;
        QCheckBox *expiryCB;
        QLabel *expiryLabel;
        KDateComboBox *expiryDE;
        QComboBox *keyAlgoCB;
        QLabel *keyAlgoLabel;
        AnimatedExpander *expander;

        UI(QWidget *dialog)
        {
            auto mainLayout = new QVBoxLayout{dialog};

            infoLabel = new QLabel{dialog};
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            scrollArea = new KAdjustingScrollArea{dialog};
            scrollArea->setFocusPolicy(Qt::NoFocus);
            scrollArea->setFrameStyle(QFrame::NoFrame);
            scrollArea->setBackgroundRole(dialog->backgroundRole());
            scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
            auto widget = new QWidget;
            scrollArea->setWidget(widget);
            auto scrollAreaLayout = new QVBoxLayout(widget);
            scrollAreaLayout->setContentsMargins(0, 0, 0, 0);

            nameAndEmail = new NameAndEmailWidget{dialog};
            nameAndEmail->layout()->setContentsMargins(0, 0, 0, 0);
            scrollAreaLayout->addWidget(nameAndEmail);

            withPassCheckBox = new QCheckBox{i18n("Protect the generated key with a passphrase."), dialog};
            withPassCheckBox->setToolTip(
                i18n("Encrypts the secret key with an unrecoverable passphrase. You will be asked for the passphrase during key generation."));
            scrollAreaLayout->addWidget(withPassCheckBox);

            expander = new AnimatedExpander(i18n("Advanced options"), {}, dialog);
            scrollAreaLayout->addWidget(expander);

            auto advancedLayout = new QVBoxLayout;
            expander->setContentLayout(advancedLayout);

            keyAlgoLabel = new QLabel(dialog);
            keyAlgoLabel->setText(i18nc("The algorithm and strength of encryption key", "Key Material"));
            auto font = keyAlgoLabel->font();
            font.setBold(true);
            keyAlgoLabel->setFont(font);
            advancedLayout->addWidget(keyAlgoLabel);

            keyAlgoCB = new QComboBox(dialog);
            keyAlgoLabel->setBuddy(keyAlgoCB);
            advancedLayout->addWidget(keyAlgoCB);

            {
                auto hbox = new QHBoxLayout;

                expiryCB = new QCheckBox{dialog};
                expiryCB->setAccessibleName(Expiration::validUntilLabel());
                hbox->addWidget(expiryCB);

                expiryLabel = new QLabel{Expiration::validUntilLabel(), dialog};
                hbox->addWidget(expiryLabel);

                expiryDE = new KDateComboBox(dialog);
                hbox->addWidget(expiryDE, 1);

                advancedLayout->addLayout(hbox);
            }

            scrollAreaLayout->addStretch(1);

            mainLayout->addWidget(scrollArea);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            buttonBox = new QDialogButtonBox{QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog};

            mainLayout->addWidget(buttonBox);
        }
    } ui;

public:
    explicit Private(OpenPGPCertificateCreationDialog *qq)
        : q{qq}
        , ui{qq}
        , technicalParameters{KeyParameters::OpenPGP}
    {
        q->setWindowTitle(i18nc("title:window", "Create OpenPGP Certificate"));

        OpenPGPCertificateCreationConfig settings;
        const auto requiredFields = settings.requiredFields();
        const auto nameIsRequired = requiredFields.contains(QLatin1StringView{"NAME!"}, Qt::CaseInsensitive);
        const auto emailIsRequired = requiredFields.contains(QLatin1StringView{"EMAIL!"}, Qt::CaseInsensitive);

        ui.infoLabel->setText(nameIsRequired || emailIsRequired //
                                  ? i18n("Enter a name and an email address to use for the certificate.")
                                  : i18n("Enter a name and/or an email address to use for the certificate."));

        ui.nameAndEmail->setNameIsRequired(nameIsRequired);
        ui.nameAndEmail->setNameLabel(settings.nameLabel());
        const auto nameHint = settings.nameHint();
        ui.nameAndEmail->setNameHint(nameHint.isEmpty() ? settings.namePlaceholder() : nameHint);
        ui.nameAndEmail->setNamePattern(settings.nameRegex());
        ui.nameAndEmail->setEmailIsRequired(emailIsRequired);
        ui.nameAndEmail->setEmailLabel(settings.emailLabel());
        const auto emailHint = settings.emailHint();
        ui.nameAndEmail->setEmailHint(emailHint.isEmpty() ? settings.emailPlaceholder() : emailHint);
        ui.nameAndEmail->setEmailPattern(settings.emailRegex());

        ui.expander->setVisible(!settings.hideAdvanced());

        const auto conf = QGpgME::cryptoConfig();
        const auto entry = getCryptoConfigEntry(conf, "gpg-agent", "enforce-passphrase-constraints");
        if (entry && entry->boolValue()) {
            qCDebug(LIBKLEO_LOG) << "Disabling passphrase check box because of agent config.";
            ui.withPassCheckBox->setEnabled(false);
            ui.withPassCheckBox->setChecked(true);
        } else {
            ui.withPassCheckBox->setChecked(settings.withPassphrase());
            ui.withPassCheckBox->setEnabled(!settings.isWithPassphraseImmutable());
        }

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, [this]() {
            checkAccept();
        });
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        for (const auto &algorithm : DeVSCompliance::isActive() ? DeVSCompliance::compliantAlgorithms() : availableAlgorithms()) {
            ui.keyAlgoCB->addItem(QString::fromStdString(algorithm), QString::fromStdString(algorithm));
        }
        auto cryptoConfig = QGpgME::cryptoConfig();
        if (cryptoConfig) {
            auto pubkeyEntry = getCryptoConfigEntry(QGpgME::cryptoConfig(), "gpg", "default_pubkey_algo");
            if (pubkeyEntry) {
                auto algo = pubkeyEntry->stringValue().split(QLatin1Char('/'))[0];
                if (algo == QLatin1StringView("ed25519")) {
                    algo = QStringLiteral("curve25519");
                } else if (algo == QLatin1StringView("ed448")) {
                    algo = QStringLiteral("curve448");
                }
                auto index = ui.keyAlgoCB->findData(algo);
                if (index != -1) {
                    ui.keyAlgoCB->setCurrentIndex(index);
                } else {
                    ui.keyAlgoCB->setCurrentIndex(0);
                }
            } else {
                ui.keyAlgoCB->setCurrentIndex(0);
            }
        } else {
            ui.keyAlgoCB->setCurrentIndex(0);
        }

        Kleo::Expiration::setUpExpirationDateComboBox(ui.expiryDE);
        ui.expiryCB->setEnabled(true);
        setExpiryDate(defaultExpirationDate(Kleo::Expiration::ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
        if (unlimitedValidityIsAllowed()) {
            ui.expiryLabel->setEnabled(ui.expiryCB->isChecked());
            ui.expiryDE->setEnabled(ui.expiryCB->isChecked());
        } else {
            ui.expiryCB->setEnabled(false);
            ui.expiryCB->setVisible(false);
        }
        connect(ui.expiryCB, &QAbstractButton::toggled, q, [this](bool checked) {
            ui.expiryLabel->setEnabled(checked);
            ui.expiryDE->setEnabled(checked);
            if (checked && !ui.expiryDE->isValid()) {
                setExpiryDate(defaultExpirationDate(Kleo::Expiration::ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
            }
            updateTechnicalParameters();
        });
        connect(ui.expiryDE, &KDateComboBox::dateChanged, q, [this]() {
            updateTechnicalParameters();
        });
        connect(ui.keyAlgoCB, &QComboBox::currentIndexChanged, q, [this]() {
            updateTechnicalParameters();
        });
        updateTechnicalParameters(); // set key parameters to default values for OpenPGP
        connect(ui.expander, &AnimatedExpander::startExpanding, q, [this]() {
            const auto sh = q->sizeHint();
            const auto margins = q->layout()->contentsMargins();
            q->resize(std::max(sh.width(), ui.expander->contentWidth() + margins.left() + margins.right()), sh.height() + ui.expander->contentHeight());
        });
    }

private:
    void updateTechnicalParameters()
    {
        technicalParameters = KeyParameters{KeyParameters::OpenPGP};
        auto keyType = GpgME::Subkey::AlgoUnknown;
        auto subkeyType = GpgME::Subkey::AlgoUnknown;
        auto algoString = ui.keyAlgoCB->currentData().toString();
        if (algoString.startsWith(QStringLiteral("rsa"))) {
            keyType = GpgME::Subkey::AlgoRSA;
            subkeyType = GpgME::Subkey::AlgoRSA;
            const auto strength = algoString.mid(3).toInt();
            technicalParameters.setKeyLength(strength);
            technicalParameters.setSubkeyLength(strength);
        } else if (algoString == QLatin1StringView("curve25519") || algoString == QLatin1StringView("curve448")) {
            keyType = GpgME::Subkey::AlgoEDDSA;
            subkeyType = GpgME::Subkey::AlgoECDH;
            if (algoString.endsWith(QStringLiteral("25519"))) {
                technicalParameters.setKeyCurve(QStringLiteral("ed25519"));
                technicalParameters.setSubkeyCurve(QStringLiteral("cv25519"));
            } else {
                technicalParameters.setKeyCurve(QStringLiteral("ed448"));
                technicalParameters.setSubkeyCurve(QStringLiteral("cv448"));
            }
#if GPGMEPP_SUPPORTS_KYBER
        } else if (algoString == "ky768_bp256"_L1) {
            keyType = GpgME::Subkey::AlgoECDSA;
            subkeyType = GpgME::Subkey::AlgoKyber;
            technicalParameters.setKeyCurve(u"brainpoolP256r1"_s);
            technicalParameters.setSubkeyCurve(u"brainpoolP256r1"_s);
            technicalParameters.setSubkeyLength(768);
        } else if (algoString == "ky1024_bp384"_L1) {
            keyType = GpgME::Subkey::AlgoECDSA;
            subkeyType = GpgME::Subkey::AlgoKyber;
            technicalParameters.setKeyCurve(u"brainpoolP384r1"_s);
            technicalParameters.setSubkeyCurve(u"brainpoolP384r1"_s);
            technicalParameters.setSubkeyLength(1024);
#endif
        } else {
            keyType = GpgME::Subkey::AlgoECDSA;
            subkeyType = GpgME::Subkey::AlgoECDH;
            technicalParameters.setKeyCurve(algoString);
            technicalParameters.setSubkeyCurve(algoString);
        }
        technicalParameters.setKeyType(keyType);
        technicalParameters.setSubkeyType(subkeyType);

        technicalParameters.setKeyUsage(KeyUsage(KeyUsage::Certify | KeyUsage::Sign));
        technicalParameters.setSubkeyUsage(KeyUsage(KeyUsage::Encrypt));

        technicalParameters.setExpirationDate(expiryDate());
        // name and email are set later
    }

    QDate expiryDate() const
    {
        return ui.expiryCB->isChecked() ? ui.expiryDE->date() : QDate{};
    }

    void setTechnicalParameters(const KeyParameters &parameters)
    {
        int index = -1;
        if (parameters.keyType() == GpgME::Subkey::AlgoRSA) {
            index = ui.keyAlgoCB->findData(QStringLiteral("rsa%1").arg(parameters.keyLength()));
        } else if (parameters.keyCurve() == QLatin1StringView("ed25519")) {
            index = ui.keyAlgoCB->findData(QStringLiteral("curve25519"));
        } else if (parameters.keyCurve() == QLatin1StringView("ed448")) {
            index = ui.keyAlgoCB->findData(QStringLiteral("curve448"));
#if GPGMEPP_SUPPORTS_KYBER
        } else if (parameters.subkeyType() == GpgME::Subkey::AlgoKyber) {
            if (parameters.subkeyLength() == 768 && parameters.keyCurve() == "brainpoolP256r1"_L1) {
                index = ui.keyAlgoCB->findData("ky768_bp256"_L1);
            } else if (parameters.subkeyLength() == 1024 && parameters.keyCurve() == "brainpoolP384r1"_L1) {
                index = ui.keyAlgoCB->findData("ky1024_bp384"_L1);
            } else {
                qCDebug(LIBKLEO_LOG) << __func__ << "Unsupported Kyber parameters" << parameters.subkeyLength() << parameters.keyCurve();
            }
#endif
        } else {
            index = ui.keyAlgoCB->findData(parameters.keyCurve());
        }
        if (index >= 0) {
            ui.keyAlgoCB->setCurrentIndex(index);
        }
        setExpiryDate(parameters.expirationDate());
    }

    void checkAccept()
    {
        QStringList errors;
        if (ui.nameAndEmail->userID().isEmpty() && !ui.nameAndEmail->nameIsRequired() && !ui.nameAndEmail->emailIsRequired()) {
            errors.push_back(i18n("Enter a name or an email address."));
        }
        const auto nameError = ui.nameAndEmail->nameError();
        if (!nameError.isEmpty()) {
            errors.push_back(nameError);
        }
        const auto emailError = ui.nameAndEmail->emailError();
        if (!emailError.isEmpty()) {
            errors.push_back(emailError);
        }
        if (!Expiration::isValidExpirationDate(expiryDate())) {
            errors.push_back(Expiration::validityPeriodHint());
        }
        if (errors.size() > 1) {
            KMessageBox::errorList(q, i18n("There is a problem."), errors);
        } else if (!errors.empty()) {
            KMessageBox::error(q, errors.first());
        } else {
            q->accept();
        }
    }

    QDate forceDateIntoAllowedRange(QDate date) const
    {
        const auto minDate = ui.expiryDE->minimumDate();
        if (minDate.isValid() && date < minDate) {
            date = minDate;
        }
        const auto maxDate = ui.expiryDE->maximumDate();
        if (maxDate.isValid() && date > maxDate) {
            date = maxDate;
        }
        return date;
    }

    void setExpiryDate(QDate date)
    {
        if (date.isValid()) {
            ui.expiryDE->setDate(forceDateIntoAllowedRange(date));
        } else {
            // check if unlimited validity is allowed
            if (unlimitedValidityIsAllowed()) {
                ui.expiryDE->setDate(date);
            }
        }
        if (ui.expiryCB->isEnabled()) {
            ui.expiryCB->setChecked(ui.expiryDE->isValid());
        }
    }

private:
    KeyParameters technicalParameters;
};

OpenPGPCertificateCreationDialog::OpenPGPCertificateCreationDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d(new Private{this})
{
    const auto sh = sizeHint();
    const auto margins = layout()->contentsMargins();
    resize(std::max(sh.width(), d->ui.expander->contentWidth() + margins.left() + margins.right()), sh.height());
}

OpenPGPCertificateCreationDialog::~OpenPGPCertificateCreationDialog() = default;

void OpenPGPCertificateCreationDialog::setName(const QString &name)
{
    d->ui.nameAndEmail->setName(name);
}

QString OpenPGPCertificateCreationDialog::name() const
{
    return d->ui.nameAndEmail->name();
}

void OpenPGPCertificateCreationDialog::setEmail(const QString &email)
{
    d->ui.nameAndEmail->setEmail(email);
}

QString OpenPGPCertificateCreationDialog::email() const
{
    return d->ui.nameAndEmail->email();
}

void Kleo::OpenPGPCertificateCreationDialog::setKeyParameters(const Kleo::KeyParameters &parameters)
{
    setName(parameters.name());
    const auto emails = parameters.emails();
    if (!emails.empty()) {
        setEmail(emails.front());
    }
    d->setTechnicalParameters(parameters);
}

KeyParameters OpenPGPCertificateCreationDialog::keyParameters() const
{
    // set name and email on a copy of the technical parameters
    auto parameters = d->technicalParameters;
    if (!name().isEmpty()) {
        parameters.setName(name());
    }
    if (!email().isEmpty()) {
        parameters.setEmail(email());
    }
    return parameters;
}

void Kleo::OpenPGPCertificateCreationDialog::setProtectKeyWithPassword(bool protectKey)
{
    d->ui.withPassCheckBox->setChecked(protectKey);
}

bool OpenPGPCertificateCreationDialog::protectKeyWithPassword() const
{
    return d->ui.withPassCheckBox->isChecked();
}

void OpenPGPCertificateCreationDialog::setInfoText(const QString &text)
{
    d->ui.infoLabel->setText(text);
}

#include "moc_openpgpcertificatecreationdialog.cpp"
