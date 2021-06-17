/*
    ui/editdirectoryservicedialog.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "editdirectoryservicedialog.h"

#include "kleo/keyserverconfig.h"
#include "utils/algorithm.h"
#include "utils/gnupg.h"

#include <KCollapsibleGroupBox>
#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KPasswordLineEdit>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QButtonGroup>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QVBoxLayout>

using namespace Kleo;

namespace
{
int defaultPort(KeyserverConnection connection)
{
    return connection == KeyserverConnection::TunnelThroughTLS ? 636 : 389;
}
}

class EditDirectoryServiceDialog::Private
{
    EditDirectoryServiceDialog *const q;

    struct Ui {
        QLineEdit *hostEdit = nullptr;
        QSpinBox *portSpinBox = nullptr;
        QCheckBox *useDefaultPortCheckBox = nullptr;
        QButtonGroup *authenticationGroup = nullptr;
        QLineEdit *userEdit = nullptr;
        KPasswordLineEdit *passwordEdit = nullptr;
        QButtonGroup *connectionGroup = nullptr;
        KCollapsibleGroupBox *advancedSettings = nullptr;
        QLineEdit *baseDnEdit = nullptr;
        QLineEdit *additionalFlagsEdit = nullptr;
        QDialogButtonBox *buttonBox = nullptr;

        Ui(QWidget *parent)
            : hostEdit{new QLineEdit{parent}}
            , portSpinBox{new QSpinBox{parent}}
            , useDefaultPortCheckBox{new QCheckBox{parent}}
            , authenticationGroup{new QButtonGroup{parent}}
            , userEdit{new QLineEdit{parent}}
            , passwordEdit{new KPasswordLineEdit{parent}}
            , connectionGroup{new QButtonGroup{parent}}
            , advancedSettings{new KCollapsibleGroupBox{parent}}
            , baseDnEdit{new QLineEdit{parent}}
            , additionalFlagsEdit{new QLineEdit{parent}}
            , buttonBox{new QDialogButtonBox{parent}}
        {
#define SET_OBJECT_NAME( x ) x->setObjectName(QStringLiteral( #x ));
            SET_OBJECT_NAME(hostEdit)
            SET_OBJECT_NAME(portSpinBox)
            SET_OBJECT_NAME(useDefaultPortCheckBox)
            SET_OBJECT_NAME(authenticationGroup)
            SET_OBJECT_NAME(userEdit)
            SET_OBJECT_NAME(passwordEdit)
            SET_OBJECT_NAME(connectionGroup)
            SET_OBJECT_NAME(advancedSettings)
            SET_OBJECT_NAME(baseDnEdit)
            SET_OBJECT_NAME(additionalFlagsEdit)
            SET_OBJECT_NAME(buttonBox)
#undef SET_OBJECT_NAME
            auto mainLayout = new QVBoxLayout{parent};

            auto serverWidget = new QWidget{parent};
            {
                auto layout = new QGridLayout{serverWidget};
                layout->setColumnStretch(2, 1);
                int row = 0;
                layout->addWidget(new QLabel{i18n("Host:")}, row, 0);
                hostEdit->setToolTip(i18nc("@info:tooltip",
                                           "Enter the name or IP address of the server hosting the directory service."));
                hostEdit->setClearButtonEnabled(true);
                layout->addWidget(hostEdit, row, 1, 1, -1);
                ++row;
                layout->addWidget(new QLabel{i18n("Port:")}, row, 0);
                portSpinBox->setRange(1, USHRT_MAX);
                portSpinBox->setToolTip(i18nc("@info:tooltip",
                                              "<b>(Optional, the default is fine in most cases)</b> "
                                              "Pick the port number the directory service is listening on."));
                layout->addWidget(portSpinBox, row, 1);
                useDefaultPortCheckBox->setText(i18n("Use default"));
                useDefaultPortCheckBox->setChecked(true);
                layout->addWidget(useDefaultPortCheckBox, row, 2);
            }
            mainLayout->addWidget(serverWidget);

            auto authenticationWidget = new QGroupBox{i18n("Authentication"), parent};
            {
                auto layout = new QVBoxLayout{authenticationWidget};
                {
                    auto radioButton = new QRadioButton{i18n("Anonymous")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Use an anonymous LDAP server that does not require authentication."));
                    radioButton->setChecked(true);
                    authenticationGroup->addButton(radioButton, static_cast<int>(KeyserverAuthentication::Anonymous));
                    layout->addWidget(radioButton);
                }
                {
                    auto radioButton = new QRadioButton{i18n("Authenticate via Active Directory")};
                    if (!engineIsVersion(2, 2, 28, GpgME::GpgSMEngine)) {
                        radioButton->setText(i18n("Authenticate via Active Directory (requires GnuPG 2.2.28 or later)"));
                    }
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "On Windows, authenticate to the LDAP server using the Active Directory with the current user."));
                    authenticationGroup->addButton(radioButton, static_cast<int>(KeyserverAuthentication::ActiveDirectory));
                    layout->addWidget(radioButton);
                }
                {
                    auto radioButton = new QRadioButton{i18n("Authenticate with user and password")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Authenticate to the LDAP server with your LDAP credentials."));
                    authenticationGroup->addButton(radioButton, static_cast<int>(KeyserverAuthentication::Password));
                    layout->addWidget(radioButton);
                }

                auto credentialsWidget = new QWidget{parent};
                {
                    auto layout = new QGridLayout{credentialsWidget};
                    layout->setColumnStretch(1, 1);
                    int row = 0;
                    layout->addWidget(new QLabel{i18n("User:")}, row, 0);
                    userEdit->setToolTip(i18nc("@info:tooltip",
                                               "Enter your LDAP user resp. Bind DN for authenticating to the LDAP server."));
                    userEdit->setClearButtonEnabled(true);
                    layout->addWidget(userEdit, row, 1);
                    ++row;
                    layout->addWidget(new QLabel{i18n("Password:")}, row, 0);
                    passwordEdit->setToolTip(xi18nc("@info:tooltip",
                                                    "Enter your password for authenticating to the LDAP server.<nl/>"
                                                    "<warning>The password will be saved in the clear "
                                                    "in a configuration file in your home directory.</warning>"));
                    passwordEdit->setClearButtonEnabled(true);
                    layout->addWidget(passwordEdit, row, 1);
                }
                layout->addWidget(credentialsWidget);
            }
            mainLayout->addWidget(authenticationWidget);

            auto securityWidget = new QGroupBox{i18n("Connection Security"), parent};
            if (!engineIsVersion(2, 2, 28, GpgME::GpgSMEngine)) {
                securityWidget->setTitle(i18n("Connection Security (requires GnuPG 2.2.28 or later)"));
            }
            {
                auto layout = new QVBoxLayout{securityWidget};
                {
                    auto radioButton = new QRadioButton{i18n("Use default connection (probably not TLS secured)")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Use GnuPG's default to connect to the LDAP server. "
                                                  "By default, GnuPG 2.3 and earlier use a plain, not TLS secured connection. "
                                                  "<b>(Not recommended)</b>"));
                    radioButton->setChecked(true);
                    connectionGroup->addButton(radioButton, static_cast<int>(KeyserverConnection::Default));
                    layout->addWidget(radioButton);
                }
                {
                    auto radioButton = new QRadioButton{i18n("Do not use a TLS secured connection")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Use a plain, not TLS secured connection to connect to the LDAP server. "
                                                  "<b>(Not recommended)</b>"));
                    connectionGroup->addButton(radioButton, static_cast<int>(KeyserverConnection::Plain));
                    layout->addWidget(radioButton);
                }
                {
                    auto radioButton = new QRadioButton{i18n("Use TLS secured connection")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Use a standard TLS secured connection (initiated with STARTTLS) "
                                                  "to connect to the LDAP server. "
                                                  "<b>(Recommended)</b>"));
                    connectionGroup->addButton(radioButton, static_cast<int>(KeyserverConnection::UseSTARTTLS));
                    layout->addWidget(radioButton);
                }
                {
                    auto radioButton = new QRadioButton{i18n("Tunnel LDAP through a TLS connection")};
                    radioButton->setToolTip(i18nc("@info:tooltip",
                                                  "Use a TLS secured connection through which the connection to the "
                                                  "LDAP server is tunneled. "
                                                  "<b>(Not recommended)</b>"));
                    connectionGroup->addButton(radioButton, static_cast<int>(KeyserverConnection::TunnelThroughTLS));
                    layout->addWidget(radioButton);
                }
            }
            mainLayout->addWidget(securityWidget);

            advancedSettings->setTitle(i18n("Advanced Settings"));
            {
                auto layout = new QGridLayout{advancedSettings};
                layout->setColumnStretch(1, 1);
                int row = 0;
                layout->addWidget(new QLabel{i18n("Base DN:")}, row, 0);
                baseDnEdit->setToolTip(i18nc("@info:tooltip",
                                             "<b>(Optional, can usually be left empty)</b> "
                                             "Enter the base DN for this LDAP server to limit searches "
                                             "to only that subtree of the directory."));
                baseDnEdit->setClearButtonEnabled(true);
                layout->addWidget(baseDnEdit, row, 1);
                ++row;
                layout->addWidget(new QLabel{i18n("Additional flags:")}, row, 0);
                additionalFlagsEdit->setToolTip(i18nc("@info:tooltip",
                                                      "Here you can enter additional flags that are not yet (or no longer) "
                                                      "supported by Kleopatra. For example, older versions of GnuPG use "
                                                      "<code>ldaps</code> to request a TLS secured connection."));
                additionalFlagsEdit->setClearButtonEnabled(true);
                layout->addWidget(additionalFlagsEdit, row, 1);
            }
            mainLayout->addWidget(advancedSettings);

            mainLayout->addStretch(1);

            buttonBox->setStandardButtons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
            QPushButton *okButton = buttonBox->button(QDialogButtonBox::Ok);
            KGuiItem::assign(okButton, KStandardGuiItem::ok());
            KGuiItem::assign(buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());
            mainLayout->addWidget(buttonBox);
        };
    } ui;

    QString host() const
    {
        return ui.hostEdit->text().trimmed();
    }

    int port() const
    {
        return ui.useDefaultPortCheckBox->isChecked() ? -1 : ui.portSpinBox->value();
    }

    KeyserverAuthentication authentication() const
    {
        return KeyserverAuthentication{ui.authenticationGroup->checkedId()};
    }

    QString user() const
    {
        return ui.userEdit->text().trimmed();
    }

    QString password() const
    {
        return ui.passwordEdit->password(); // not trimmed
    }

    KeyserverConnection connection() const
    {
        return KeyserverConnection{ui.connectionGroup->checkedId()};
    }

    QString baseDn() const
    {
        return ui.baseDnEdit->text().trimmed();
    }

    QStringList additionalFlags() const
    {
        return transformInPlace(ui.additionalFlagsEdit->text().split(QLatin1Char{','}, Qt::SkipEmptyParts),
                                [] (const auto &flag) { return flag.trimmed(); });
    }

    bool inputIsAcceptable() const
    {
        const bool hostIsSet = !host().isEmpty();
        const bool requiredCredentialsAreSet = authentication() != KeyserverAuthentication::Password
            || (!user().isEmpty() && !password().isEmpty());
        return hostIsSet && requiredCredentialsAreSet;
    }

    void updateWidgets()
    {
        ui.portSpinBox->setEnabled(!ui.useDefaultPortCheckBox->isChecked());
        if (ui.useDefaultPortCheckBox->isChecked()) {
            ui.portSpinBox->setValue(defaultPort(connection()));
        }

        ui.userEdit->setEnabled(authentication() == KeyserverAuthentication::Password);
        ui.passwordEdit->setEnabled(authentication() == KeyserverAuthentication::Password);

        ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(inputIsAcceptable());
    }

public:
    Private(EditDirectoryServiceDialog *q)
        : q{q}
        , ui{q}
    {
        connect(ui.hostEdit, &QLineEdit::textEdited, q, [this] () { updateWidgets(); });
        connect(ui.useDefaultPortCheckBox, &QCheckBox::toggled, q, [this] () { updateWidgets(); });
        connect(ui.authenticationGroup, &QButtonGroup::idToggled, q, [this] () { updateWidgets(); });
        connect(ui.userEdit, &QLineEdit::textEdited, q, [this] () { updateWidgets(); });
        connect(ui.passwordEdit, &KPasswordLineEdit::passwordChanged, q, [this] () { updateWidgets(); });
        connect(ui.connectionGroup, &QButtonGroup::idToggled, q, [this] () { updateWidgets(); });

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, &EditDirectoryServiceDialog::accept);
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &EditDirectoryServiceDialog::reject);

        updateWidgets();

        restoreLayout();
    }

    ~Private()
    {
        saveLayout();
    }

    void setKeyserver(const KeyserverConfig& keyserver)
    {
        ui.hostEdit->setText(keyserver.host());
        ui.useDefaultPortCheckBox->setChecked(keyserver.port() == -1);
        ui.portSpinBox->setValue(keyserver.port() == -1 ? defaultPort(keyserver.connection()) : keyserver.port());
        ui.authenticationGroup->button(static_cast<int>(keyserver.authentication()))->setChecked(true);
        ui.userEdit->setText(keyserver.user());
        ui.passwordEdit->setPassword(keyserver.password());
        ui.connectionGroup->button(static_cast<int>(keyserver.connection()))->setChecked(true);
        ui.baseDnEdit->setText(keyserver.ldapBaseDn());
        ui.additionalFlagsEdit->setText(keyserver.additionalFlags().join(QLatin1Char{','}));

        ui.advancedSettings->setExpanded(!keyserver.ldapBaseDn().isEmpty() || !keyserver.additionalFlags().empty());
        updateWidgets();
    }

    KeyserverConfig keyserver() const
    {
        KeyserverConfig keyserver;
        keyserver.setHost(host());
        keyserver.setPort(port());
        keyserver.setAuthentication(authentication());
        keyserver.setUser(user());
        keyserver.setPassword(password());
        keyserver.setConnection(connection());
        keyserver.setLdapBaseDn(baseDn());
        keyserver.setAdditionalFlags(additionalFlags());

        return keyserver;
    }

private:
    void saveLayout()
    {
        KConfigGroup configGroup{KSharedConfig::openStateConfig(), "EditDirectoryServiceDialog"};
        configGroup.writeEntry("Size", q->size());
        configGroup.sync();
    }

    void restoreLayout()
    {
        const KConfigGroup configGroup{KSharedConfig::openStateConfig(), "EditDirectoryServiceDialog"};
        const auto size = configGroup.readEntry("Size", QSize{});
        if (size.isValid()) {
            q->resize(size);
        }
    }
};

EditDirectoryServiceDialog::EditDirectoryServiceDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d{std::make_unique<Private>(this)}
{
    setWindowTitle(i18nc("@title:window", "Edit Directory Service"));
}

EditDirectoryServiceDialog::~EditDirectoryServiceDialog() = default;

void EditDirectoryServiceDialog::setKeyserver(const KeyserverConfig& keyserver)
{
    d->setKeyserver(keyserver);
}

KeyserverConfig EditDirectoryServiceDialog::keyserver() const
{
    return d->keyserver();
}
