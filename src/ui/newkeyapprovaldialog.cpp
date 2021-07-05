/*  -*- c++ -*-
    newkeyapprovaldialog.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "newkeyapprovaldialog.h"

#include "keyselectioncombo.h"
#include "progressdialog.h"
#include "kleo/defaultkeyfilter.h"
#include "utils/formatting.h"

#include <KLocalizedString>
#include <KMessageBox>

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QDesktopWidget>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QMap>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QToolTip>
#include <QVBoxLayout>

#include <QGpgME/DefaultKeyGenerationJob>
#include <QGpgME/Job>

#include <gpgme++/keygenerationresult.h>
#include <gpgme++/key.h>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

QDebug operator<<(QDebug debug, const GpgME::Key &key)
{
    if (key.isNull()) {
        debug << "Null";
    } else {
        debug << Formatting::summaryLine(key);
    }
    return debug.maybeSpace();
}

namespace {
class EncryptFilter: public DefaultKeyFilter
{
public:
    EncryptFilter() : DefaultKeyFilter()
    {
        setCanEncrypt(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_encryptFilter = std::shared_ptr<KeyFilter>(new EncryptFilter);

class OpenPGPFilter: public DefaultKeyFilter
{
public:
    OpenPGPFilter() : DefaultKeyFilter()
    {
        setIsOpenPGP(DefaultKeyFilter::Set);
        setCanEncrypt(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_pgpEncryptFilter = std::shared_ptr<KeyFilter> (new OpenPGPFilter);

class OpenPGPSignFilter: public DefaultKeyFilter
{
public:
    OpenPGPSignFilter() : DefaultKeyFilter()
    {
        /* Also list unusable keys to make it transparent why they are unusable */
        setDisabled(DefaultKeyFilter::NotSet);
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setCanSign(DefaultKeyFilter::Set);
        setHasSecret(DefaultKeyFilter::Set);
        setIsOpenPGP(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_pgpSignFilter = std::shared_ptr<KeyFilter> (new OpenPGPSignFilter);

class SMIMEFilter: public DefaultKeyFilter
{
public:
    SMIMEFilter(): DefaultKeyFilter()
    {
        setIsOpenPGP(DefaultKeyFilter::NotSet);
        setCanEncrypt(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_smimeEncryptFilter = std::shared_ptr<KeyFilter> (new SMIMEFilter);

class SMIMESignFilter: public DefaultKeyFilter
{
public:
    SMIMESignFilter(): DefaultKeyFilter()
    {
        setDisabled(DefaultKeyFilter::NotSet);
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setCanSign(DefaultKeyFilter::Set);
        setIsOpenPGP(DefaultKeyFilter::NotSet);
        setHasSecret(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_smimeSignFilter = std::shared_ptr<KeyFilter> (new SMIMESignFilter);

/* Some decoration and a button to remove the filter for a keyselectioncombo */
class ComboWidget: public QWidget
{
    Q_OBJECT
public:
    explicit ComboWidget(KeySelectionCombo *combo):
        mCombo(combo),
        mFilterBtn(new QPushButton)
    {
        auto hLay = new QHBoxLayout(this);
        auto infoBtn = new QPushButton;
        infoBtn->setIcon(QIcon::fromTheme(QStringLiteral("help-contextual")));
        infoBtn->setIconSize(QSize(22,22));
        infoBtn->setFlat(true);
        hLay->addWidget(infoBtn);
        hLay->addWidget(combo, 1);
        hLay->addWidget(mFilterBtn, 0);

        connect(infoBtn, &QPushButton::clicked, this, [this, infoBtn] () {
            QToolTip::showText(infoBtn->mapToGlobal(QPoint()) + QPoint(infoBtn->width(), 0),
                    mCombo->currentData(Qt::ToolTipRole).toString(), infoBtn, QRect(), 30000);
        });

        // FIXME: This is ugly to enforce but otherwise the
        // icon is broken.
        combo->setMinimumHeight(22);
        mFilterBtn->setMinimumHeight(23);

        updateFilterButton();

        connect(mFilterBtn, &QPushButton::clicked, this, [this] () {
            const QString curFilter = mCombo->idFilter();
            if (curFilter.isEmpty()) {
                setIdFilter(mLastIdFilter);
                mLastIdFilter = QString();
            } else {
                setIdFilter(QString());
                mLastIdFilter = curFilter;
            }
        });
    }

    void setIdFilter(const QString &id)
    {
        mCombo->setIdFilter(id);
        updateFilterButton();
    }

    void updateFilterButton()
    {
        if (mCombo->idFilter().isEmpty()) {
            mFilterBtn->setIcon(QIcon::fromTheme(QStringLiteral("kt-add-filters")));
            mFilterBtn->setToolTip(i18n("Show keys matching the email address"));
        } else {
            mFilterBtn->setIcon(QIcon::fromTheme(QStringLiteral("kt-remove-filters")));
            mFilterBtn->setToolTip(i18n("Show all keys"));
        }
    }

    KeySelectionCombo *combo()
    {
        return mCombo;
    }

    GpgME::Protocol fixedProtocol() const
    {
        return mFixedProtocol;
    }

    void setFixedProtocol(GpgME::Protocol proto)
    {
        mFixedProtocol = proto;
    }

private:
    KeySelectionCombo *mCombo;
    QPushButton *mFilterBtn;
    QString mLastIdFilter;
    GpgME::Protocol mFixedProtocol = GpgME::UnknownProtocol;
};

static enum GpgME::UserID::Validity keyValidity(const GpgME::Key &key)
{
    enum GpgME::UserID::Validity validity = GpgME::UserID::Validity::Unknown;

    for (const auto &uid: key.userIDs()) {
        if (validity == GpgME::UserID::Validity::Unknown
            || validity > uid.validity()) {
            validity = uid.validity();
        }
    }

    return validity;
}

static bool key_has_addr(const GpgME::Key &key, const QString &addr)
{
    for (const auto &uid: key.userIDs()) {
        if (QString::fromStdString(uid.addrSpec()).toLower() == addr.toLower()) {
            return true;
        }
    }
    return false;
}

bool anyKeyHasProtocol(const std::vector<Key> &keys, Protocol protocol)
{
    return std::any_of(std::begin(keys), std::end(keys), [protocol] (const auto &key) { return key.protocol() == protocol; });
}

Key findfirstKeyOfType(const std::vector<Key> &keys, Protocol protocol)
{
    const auto it = std::find_if(std::begin(keys), std::end(keys), [protocol] (const auto &key) { return key.protocol() == protocol; });
    return it != std::end(keys) ? *it : Key();
}

} // namespace

class NewKeyApprovalDialog::Private
{
private:
    enum Action {
        Unset,
        GenerateKey,
        IgnoreKey,
    };
public:
    enum {
        OpenPGPButtonId = 1,
        SMIMEButtonId = 2
    };

    Private(NewKeyApprovalDialog *qq,
            bool encrypt,
            bool sign,
            GpgME::Protocol forcedProtocol,
            GpgME::Protocol presetProtocol,
            const QString &sender,
            bool allowMixed)
        : mForcedProtocol{forcedProtocol}
        , mSender{sender}
        , mSign{sign}
        , mEncrypt{encrypt}
        , mAllowMixed{allowMixed}
        , q{qq}
    {
        Q_ASSERT(forcedProtocol == GpgME::UnknownProtocol || presetProtocol == GpgME::UnknownProtocol || presetProtocol == forcedProtocol);
        Q_ASSERT(!allowMixed || (allowMixed && forcedProtocol == GpgME::UnknownProtocol));
        Q_ASSERT(!(!allowMixed && presetProtocol == GpgME::UnknownProtocol));

        // We do the translation here to avoid having the same string multiple times.
        mGenerateTooltip = i18nc("@info:tooltip for a 'Generate new key pair' action "
                                 "in a combobox when a user does not yet have an OpenPGP or S/MIME key.",
                                 "Generate a new key using your E-Mail address.<br/><br/>"
                                 "The key is necessary to decrypt and sign E-Mails. "
                                 "You will be asked for a passphrase to protect this key and the protected key "
                                 "will be stored in your home directory.");
        mMainLay = new QVBoxLayout;

        QDialogButtonBox *btnBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        mOkButton = btnBox->button(QDialogButtonBox::Ok);
#ifndef NDEBUG
        mOkButton->setObjectName(QStringLiteral("ok button"));
#endif
        QObject::connect (btnBox, &QDialogButtonBox::accepted, q, [this] () {
                accepted();
            });
        QObject::connect (btnBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        mScrollArea = new QScrollArea;
        mScrollArea->setWidget(new QWidget);
        mScrollLayout = new QVBoxLayout;
        mScrollArea->widget()->setLayout(mScrollLayout);
        mScrollArea->setWidgetResizable(true);
        mScrollArea->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContentsOnFirstShow);
        mScrollArea->setFrameStyle(QFrame::NoFrame);
        mScrollLayout->setContentsMargins(0, 0, 0, 0);

        q->setWindowTitle(i18nc("@title:window", "Security approval"));

        auto fmtLayout = new QHBoxLayout;
        mFormatBtns = new QButtonGroup(qq);
        QAbstractButton *pgpBtn;
        QAbstractButton *smimeBtn;
        if (mAllowMixed) {
            pgpBtn = new QCheckBox(i18n("OpenPGP"));
            smimeBtn = new QCheckBox(i18n("S/MIME"));
        } else {
            pgpBtn = new QRadioButton(i18n("OpenPGP"));
            smimeBtn = new QRadioButton(i18n("S/MIME"));
        }
#ifndef NDEBUG
        pgpBtn->setObjectName(QStringLiteral("openpgp button"));
        smimeBtn->setObjectName(QStringLiteral("smime button"));
#endif
        mFormatBtns->addButton(pgpBtn, OpenPGPButtonId);
        mFormatBtns->addButton(smimeBtn, SMIMEButtonId);
        mFormatBtns->setExclusive(!mAllowMixed);

        fmtLayout->addStretch(-1);
        fmtLayout->addWidget(pgpBtn);
        fmtLayout->addWidget(smimeBtn);
        mMainLay->addLayout(fmtLayout);

        if (mForcedProtocol != GpgME::UnknownProtocol) {
            pgpBtn->setChecked(mForcedProtocol == GpgME::OpenPGP);
            smimeBtn->setChecked(mForcedProtocol == GpgME::CMS);
            pgpBtn->setVisible(false);
            smimeBtn->setVisible(false);
        } else {
            pgpBtn->setChecked(presetProtocol == GpgME::OpenPGP || presetProtocol == GpgME::UnknownProtocol);
            smimeBtn->setChecked(presetProtocol == GpgME::CMS || presetProtocol == GpgME::UnknownProtocol);
        }

        QObject::connect(mFormatBtns, &QButtonGroup::idClicked,
                         q, [this](int buttonId) {
                             // ensure that at least one protocol button is checked
                             if (mAllowMixed
                                    && !mFormatBtns->button(OpenPGPButtonId)->isChecked()
                                    && !mFormatBtns->button(SMIMEButtonId)->isChecked()) {
                                 mFormatBtns->button(buttonId == OpenPGPButtonId ? SMIMEButtonId : OpenPGPButtonId)->setChecked(true);
                             }
                             updateWidgets();
                        });

        mMainLay->addWidget(mScrollArea);

        mComplianceLbl = new QLabel;
        mComplianceLbl->setVisible(false);
#ifndef NDEBUG
        mComplianceLbl->setObjectName(QStringLiteral("compliance label"));
#endif

        auto btnLayout = new QHBoxLayout;
        btnLayout->addWidget(mComplianceLbl);
        btnLayout->addWidget(btnBox);
        mMainLay->addLayout(btnLayout);

        q->setLayout(mMainLay);
    }

    ~Private() = default;

    Protocol currentProtocol()
    {
        const bool openPGPButtonChecked = mFormatBtns->button(OpenPGPButtonId)->isChecked();
        const bool smimeButtonChecked = mFormatBtns->button(SMIMEButtonId)->isChecked();
        if (mAllowMixed) {
            if (openPGPButtonChecked && !smimeButtonChecked) {
                return OpenPGP;
            }
            if (!openPGPButtonChecked && smimeButtonChecked) {
                return CMS;
            }
        } else if (openPGPButtonChecked) {
            return OpenPGP;
        } else if (smimeButtonChecked) {
            return CMS;
        }
        return UnknownProtocol;
    }

    auto findVisibleKeySelectionComboWithGenerateKey()
    {
        const auto it = std::find_if(std::begin(mAllCombos), std::end(mAllCombos),
                                     [] (auto combo) {
                                         return combo->isVisible()
                                             && combo->currentData(Qt::UserRole).toInt() == GenerateKey;
                                     });
        return it != std::end(mAllCombos) ? *it : nullptr;
    }

    void generateKey(KeySelectionCombo *combo)
    {
        const auto &addr = combo->property("address").toString();
        auto job = new QGpgME::DefaultKeyGenerationJob(q);
        auto progress = new Kleo::ProgressDialog(job, i18n("Generating key for '%1'...", addr) + QStringLiteral("\n\n") +
                                                 i18n("This can take several minutes."), q);
        progress->setWindowFlags(progress->windowFlags() & ~Qt::WindowContextHelpButtonHint);
        progress->setWindowTitle(i18nc("@title:window", "Key generation"));
        progress->setModal(true);
        progress->setAutoClose(true);
        progress->setMinimumDuration(0);
        progress->setValue(0);

        mRunningJobs << job;
        connect (job, &QGpgME::DefaultKeyGenerationJob::result, q,
            [this, job, combo] (const GpgME::KeyGenerationResult &result) {
                handleKeyGenResult(result, job, combo);
            });
        job->start(addr, QString());
        return;
    }

    void handleKeyGenResult(const GpgME::KeyGenerationResult &result, QGpgME::Job *job, KeySelectionCombo *combo)
    {
        mLastError = result.error();
        if (!mLastError || mLastError.isCanceled()) {
            combo->setDefaultKey(QString::fromLatin1(result.fingerprint()), GpgME::OpenPGP);
            connect (combo, &KeySelectionCombo::keyListingFinished, q, [this, job] () {
                    mRunningJobs.removeAll(job);
                });
            combo->refreshKeys();
        } else {
            mRunningJobs.removeAll(job);
        }
    }

    void checkAccepted()
    {
        if (mLastError || mLastError.isCanceled()) {
            KMessageBox::error(q, QString::fromLocal8Bit(mLastError.asString()), i18n("Operation Failed"));
            mRunningJobs.clear();
            return;
        }

        if (!mRunningJobs.empty()) {
            return;
        }

        /* Save the keys */
        mAcceptedResult.protocol = currentProtocol();
        for (const auto combo: std::as_const(mEncCombos)) {
            const auto addr = combo->property("address").toString();
            const auto key = combo->currentKey();
            if (!combo->isVisible() || key.isNull()) {
                continue;
            }
            mAcceptedResult.encryptionKeys[addr].push_back(key);
        }
        for (const auto combo: std::as_const(mSigningCombos)) {
            const auto key = combo->currentKey();
            if (!combo->isVisible() || key.isNull()) {
                continue;
            }
            mAcceptedResult.signingKeys.push_back(key);
        }

        q->accept();
    }

    void accepted()
    {
        // We can assume everything was validly resolved, otherwise
        // the OK button would have been disabled.
        // Handle custom items now.
        if (auto combo = findVisibleKeySelectionComboWithGenerateKey()) {
            generateKey(combo);
            return;
        }
        checkAccepted();
    }

    auto encryptionKeyFilter(Protocol protocol)
    {
        switch (protocol) {
        case OpenPGP:
            return s_pgpEncryptFilter;
        case CMS:
            return s_smimeEncryptFilter;
        default:
            return s_encryptFilter;
        }
    }

    void updateWidgets()
    {
        const Protocol protocol = currentProtocol();
        const auto encryptionFilter = encryptionKeyFilter(protocol);

        for (auto combo: std::as_const(mSigningCombos)) {
            auto widget = qobject_cast<ComboWidget *>(combo->parentWidget());
            if (!widget) {
                qCDebug(LIBKLEO_LOG) << "Failed to find signature combo widget";
                continue;
            }
            widget->setVisible(protocol == UnknownProtocol || widget->fixedProtocol() == UnknownProtocol || widget->fixedProtocol() == protocol);
        }
        for (auto combo: std::as_const(mEncCombos)) {
            auto widget = qobject_cast<ComboWidget *>(combo->parentWidget());
            if (!widget) {
                qCDebug(LIBKLEO_LOG) << "Failed to find combo widget";
                continue;
            }
            widget->setVisible(protocol == UnknownProtocol || widget->fixedProtocol() == UnknownProtocol || widget->fixedProtocol() == protocol);
            if (widget->isVisible() && combo->property("address") != mSender) {
                combo->setKeyFilter(encryptionFilter);
            }
        }
        // hide the labels indicating the protocol of the sender's keys if only a single protocol is active
        const auto protocolLabels = q->findChildren<QLabel *>(QStringLiteral("protocol label"));
        for (auto label: protocolLabels) {
            label->setVisible(protocol == UnknownProtocol);
        }
    }

    auto createProtocolLabel(Protocol protocol)
    {
        auto label = new QLabel(Formatting::displayName(protocol));
        label->setObjectName(QStringLiteral("protocol label"));
        return label;
    }

    ComboWidget *createSigningCombo(const QString &addr, const GpgME::Key &key, Protocol protocol = UnknownProtocol)
    {
        Q_ASSERT(!key.isNull() || protocol != UnknownProtocol);
        protocol = !key.isNull() ? key.protocol() : protocol;

        auto combo = new KeySelectionCombo();
        auto comboWidget = new ComboWidget(combo);
#ifndef NDEBUG
        combo->setObjectName(QStringLiteral("signing key"));
#endif
        if (protocol == GpgME::OpenPGP) {
            combo->setKeyFilter(s_pgpSignFilter);
        } else if (protocol == GpgME::CMS) {
            combo->setKeyFilter(s_smimeSignFilter);
        }
        if (key.isNull() || key_has_addr(key, mSender)) {
            comboWidget->setIdFilter(mSender);
        }
        comboWidget->setFixedProtocol(protocol);
        if (!key.isNull()) {
            combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()), protocol);
        }
        if (key.isNull() && protocol == OpenPGP) {
            combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("document-new")),
                                    i18n("Generate a new key pair"), GenerateKey,
                                    mGenerateTooltip);
        }
        combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("emblem-unavailable")),
                i18n("Don't confirm identity and integrity"), IgnoreKey,
                i18nc("@info:tooltip for not selecting a key for signing.",
                      "The E-Mail will not be cryptographically signed."));

        mSigningCombos << combo;
        mAllCombos << combo;
        combo->setProperty("address", addr);

        connect(combo, &KeySelectionCombo::currentKeyChanged, q, [this] () {
            updateOkButton();
        });
        connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), q, [this] () {
            updateOkButton();
        });

        return comboWidget;
    }

    void setSigningKeys(const std::vector<GpgME::Key> &preferredKeys, const std::vector<GpgME::Key> &alternativeKeys)
    {
        auto group = new QGroupBox(i18nc("Caption for signing key selection", "Confirm identity '%1' as:", mSender));
        group->setAlignment(Qt::AlignLeft);
        auto sigLayout = new QVBoxLayout(group);

        const bool mayNeedOpenPGP = mForcedProtocol != CMS;
        const bool mayNeedCMS = mForcedProtocol != OpenPGP;
        if (mayNeedOpenPGP) {
            if (mAllowMixed) {
                sigLayout->addWidget(createProtocolLabel(OpenPGP));
            }
            const Key preferredKey = findfirstKeyOfType(preferredKeys, OpenPGP);
            const Key alternativeKey = findfirstKeyOfType(alternativeKeys, OpenPGP);
            if (!preferredKey.isNull()) {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for" << preferredKey;
                auto comboWidget = createSigningCombo(mSender, preferredKey);
                sigLayout->addWidget(comboWidget);
            } else if (!alternativeKey.isNull()) {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for" << alternativeKey;
                auto comboWidget = createSigningCombo(mSender, alternativeKey);
                sigLayout->addWidget(comboWidget);
            } else {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for OpenPGP key";
                auto comboWidget = createSigningCombo(mSender, Key(), OpenPGP);
                sigLayout->addWidget(comboWidget);
            }
        }
        if (mayNeedCMS) {
            if (mAllowMixed) {
                sigLayout->addWidget(createProtocolLabel(CMS));
            }
            const Key preferredKey = findfirstKeyOfType(preferredKeys, CMS);
            const Key alternativeKey = findfirstKeyOfType(alternativeKeys, CMS);
            if (!preferredKey.isNull()) {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for" << preferredKey;
                auto comboWidget = createSigningCombo(mSender, preferredKey);
                sigLayout->addWidget(comboWidget);
            } else if (!alternativeKey.isNull()) {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for" << alternativeKey;
                auto comboWidget = createSigningCombo(mSender, alternativeKey);
                sigLayout->addWidget(comboWidget);
            } else {
                qCDebug(LIBKLEO_LOG) << "setSigningKeys - creating signing combo for S/MIME key";
                auto comboWidget = createSigningCombo(mSender, Key(), CMS);
                sigLayout->addWidget(comboWidget);
            }
        }

        mScrollLayout->addWidget(group);
    }

    ComboWidget *createEncryptionCombo(const QString &addr, const GpgME::Key &key, Protocol fixedProtocol)
    {
        auto combo = new KeySelectionCombo(false);
        auto comboWidget = new ComboWidget(combo);
#ifndef NDEBUG
        combo->setObjectName(QStringLiteral("encryption key"));
#endif
        if (fixedProtocol == GpgME::OpenPGP) {
            combo->setKeyFilter(s_pgpEncryptFilter);
        } else if (fixedProtocol == GpgME::CMS) {
            combo->setKeyFilter(s_smimeEncryptFilter);
        } else {
            combo->setKeyFilter(s_encryptFilter);
        }
        if (key.isNull() || key_has_addr (key, addr)) {
            comboWidget->setIdFilter(addr);
        }
        comboWidget->setFixedProtocol(fixedProtocol);
        if (!key.isNull()) {
            combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()), fixedProtocol);
        }

        if (addr == mSender && key.isNull() && fixedProtocol == OpenPGP) {
            combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("document-new")),
                                    i18n("Generate a new key pair"), GenerateKey,
                                    mGenerateTooltip);
        }

        combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("emblem-unavailable")),
                i18n("No key. Recipient will be unable to decrypt."), IgnoreKey,
                i18nc("@info:tooltip for No Key selected for a specific recipient.",
                        "Do not select a key for this recipient.<br/><br/>"
                        "The recipient will receive the encrypted E-Mail, but it can only "
                        "be decrypted with the other keys selected in this dialog."));

        connect(combo, &KeySelectionCombo::currentKeyChanged, q, [this] () {
            updateOkButton();
        });
        connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), q, [this] () {
            updateOkButton();
        });

        mEncCombos << combo;
        mAllCombos << combo;
        combo->setProperty("address", addr);
        return comboWidget;
    }

    void addEncryptionAddr(const QString &addr,
                           Protocol preferredKeysProtocol, const std::vector<GpgME::Key> &preferredKeys,
                           Protocol alternativeKeysProtocol, const std::vector<GpgME::Key> &alternativeKeys,
                           QGridLayout *encGrid)
    {
        if (addr == mSender) {
            const bool mayNeedOpenPGP = mForcedProtocol != CMS;
            const bool mayNeedCMS = mForcedProtocol != OpenPGP;
            if (mayNeedOpenPGP) {
                if (mAllowMixed) {
                    encGrid->addWidget(createProtocolLabel(OpenPGP), encGrid->rowCount(), 0);
                }
                for (const auto &key : preferredKeys) {
                    if (key.protocol() == OpenPGP) {
                        qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                        auto comboWidget = createEncryptionCombo(addr, key, OpenPGP);
                        encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                    }
                }
                for (const auto &key : alternativeKeys) {
                    if (key.protocol() == OpenPGP) {
                        qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                        auto comboWidget = createEncryptionCombo(addr, key, OpenPGP);
                        encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                    }
                }
                if (!anyKeyHasProtocol(preferredKeys, OpenPGP) && !anyKeyHasProtocol(alternativeKeys, OpenPGP)) {
                    qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for OpenPGP key";
                    auto comboWidget = createEncryptionCombo(addr, GpgME::Key(), OpenPGP);
                    encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                }
            }
            if (mayNeedCMS) {
                if (mAllowMixed) {
                    encGrid->addWidget(createProtocolLabel(CMS), encGrid->rowCount(), 0);
                }
                for (const auto &key : preferredKeys) {
                    if (key.protocol() == CMS) {
                        qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                        auto comboWidget = createEncryptionCombo(addr, key, CMS);
                        encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                    }
                }
                for (const auto &key : alternativeKeys) {
                    if (key.protocol() == CMS) {
                        qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                        auto comboWidget = createEncryptionCombo(addr, key, CMS);
                        encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                    }
                }
                if (!anyKeyHasProtocol(preferredKeys, CMS) && !anyKeyHasProtocol(alternativeKeys, CMS)) {
                    qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for S/MIME key";
                    auto comboWidget = createEncryptionCombo(addr, GpgME::Key(), CMS);
                    encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                }
            }
        } else {
            encGrid->addWidget(new QLabel(addr), encGrid->rowCount(), 0);

            for (const auto &key : preferredKeys) {
                qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                auto comboWidget = createEncryptionCombo(addr, key, preferredKeysProtocol);
                encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
            }
            for (const auto &key : alternativeKeys) {
                qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << key;
                auto comboWidget = createEncryptionCombo(addr, key, alternativeKeysProtocol);
                encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
            }
            if (!mAllowMixed) {
                if (preferredKeys.empty()) {
                    qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << Formatting::displayName(preferredKeysProtocol) << "key";
                    auto comboWidget = createEncryptionCombo(addr, GpgME::Key(), preferredKeysProtocol);
                    encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                }
                if (alternativeKeys.empty() && alternativeKeysProtocol != UnknownProtocol) {
                    qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for" << Formatting::displayName(alternativeKeysProtocol) << "key";
                    auto comboWidget = createEncryptionCombo(addr, GpgME::Key(), alternativeKeysProtocol);
                    encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                }
            } else {
                if (preferredKeys.empty() && alternativeKeys.empty()) {
                    qCDebug(LIBKLEO_LOG) << "setEncryptionKeys -" << addr << "- creating encryption combo for any key";
                    auto comboWidget = createEncryptionCombo(addr, GpgME::Key(), UnknownProtocol);
                    encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
                }
            }
        }
    }

    void setEncryptionKeys(Protocol preferredKeysProtocol, const QMap<QString, std::vector<GpgME::Key>> &preferredKeys,
                           Protocol alternativeKeysProtocol, const QMap<QString, std::vector<GpgME::Key>> &alternativeKeys)
    {
        {
            auto group = new QGroupBox(i18nc("Encrypt to self (email address):", "Encrypt to self (%1):", mSender));
#ifndef NDEBUG
            group->setObjectName(QStringLiteral("encrypt-to-self box"));
#endif
            group->setAlignment(Qt::AlignLeft);
            auto encGrid = new QGridLayout(group);

            addEncryptionAddr(mSender, preferredKeysProtocol, preferredKeys.value(mSender), alternativeKeysProtocol, alternativeKeys.value(mSender), encGrid);

            encGrid->setColumnStretch(1, -1);
            mScrollLayout->addWidget(group);
        }

        const bool hasOtherRecipients = std::any_of(preferredKeys.keyBegin(), preferredKeys.keyEnd(), [this](const auto &recipient) { return recipient != mSender; });
        if (hasOtherRecipients) {
            auto group = new QGroupBox(i18n("Encrypt to others:"));
#ifndef NDEBUG
            group->setObjectName(QStringLiteral("encrypt-to-others box"));
#endif
            group->setAlignment(Qt::AlignLeft);
            auto encGrid = new QGridLayout{group};

            for (auto it = std::begin(preferredKeys); it != std::end(preferredKeys); ++it) {
                const auto &address = it.key();
                const auto &keys = it.value();
                if (address != mSender) {
                    addEncryptionAddr(address, preferredKeysProtocol, keys, alternativeKeysProtocol, alternativeKeys.value(address), encGrid);
                }
            }

            encGrid->setColumnStretch(1, -1);
            mScrollLayout->addWidget(group);
        }

        mScrollLayout->addStretch(-1);
    }

    void updateOkButton()
    {
        static QString origOkText = mOkButton->text();
        const bool isGenerate = bool(findVisibleKeySelectionComboWithGenerateKey());
        const bool allVisibleEncryptionKeysAreIgnored = std::all_of(std::begin(mEncCombos), std::end(mEncCombos),
                                                                    [] (auto combo) {
                                                                        return !combo->isVisible()
                                                                            || combo->currentData(Qt::UserRole).toInt() == IgnoreKey;
                                                                    });

        // If we don't encrypt the ok button is always enabled. But otherwise
        // we only enable it if we encrypt to at least one recipient.
        mOkButton->setEnabled(!mEncrypt || !allVisibleEncryptionKeysAreIgnored);

        mOkButton->setText(isGenerate ? i18n("Generate") : origOkText);

        if (Formatting::complianceMode() != QLatin1String("de-vs")) {
            return;
        }

        // Handle compliance
        bool de_vs = true;

        const Protocol protocol = currentProtocol();

        for (const auto combo: std::as_const(mAllCombos)) {
            if (!combo->isVisible()) {
                continue;
            }
            const auto key = combo->currentKey();
            if (key.isNull()) {
                continue;
            }
            if (protocol != UnknownProtocol && key.protocol() != protocol) {
                continue;
            }
            if (!Formatting::isKeyDeVs(key) || keyValidity(key) < GpgME::UserID::Validity::Full) {
                de_vs = false;
                break;
            }
        }

        mOkButton->setIcon(QIcon::fromTheme(de_vs
                    ? QStringLiteral("security-high")
                    : QStringLiteral("security-medium")));
        mOkButton->setStyleSheet(QStringLiteral("background-color: ") + (de_vs
                    ? QStringLiteral("#D5FAE2")  // KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::PositiveBackground).color().name()
                    : QStringLiteral("#FAE9EB"))); //KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NegativeBackground).color().name()));
        mComplianceLbl->setText(de_vs
                ? i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                    "%1 communication possible.", Formatting::deVsString())
                : i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                    "%1 communication not possible.", Formatting::deVsString()));
        mComplianceLbl->setVisible(true);
    }

    GpgME::Protocol mForcedProtocol;
    QList<KeySelectionCombo *> mSigningCombos;
    QList<KeySelectionCombo *> mEncCombos;
    QList<KeySelectionCombo *> mAllCombos;
    QScrollArea *mScrollArea;
    QVBoxLayout *mScrollLayout;
    QPushButton *mOkButton;
    QVBoxLayout *mMainLay;
    QButtonGroup *mFormatBtns;
    QString mSender;
    bool mSign;
    bool mEncrypt;
    bool mAllowMixed;
    NewKeyApprovalDialog *q;
    QList <QGpgME::Job *> mRunningJobs;
    GpgME::Error mLastError;
    QLabel *mComplianceLbl;
    KeyResolver::Solution mAcceptedResult;
    QString mGenerateTooltip;
};

NewKeyApprovalDialog::NewKeyApprovalDialog(bool encrypt,
                                           bool sign,
                                           const QString &sender,
                                           KeyResolver::Solution preferredSolution,
                                           KeyResolver::Solution alternativeSolution,
                                           bool allowMixed,
                                           GpgME::Protocol forcedProtocol,
                                           QWidget *parent,
                                           Qt::WindowFlags f)
    : QDialog(parent, f)
    , d{std::make_unique<Private>(this, encrypt, sign, forcedProtocol, preferredSolution.protocol, sender, allowMixed)}
{
    if (sign) {
        d->setSigningKeys(std::move(preferredSolution.signingKeys), std::move(alternativeSolution.signingKeys));
    }
    if (encrypt) {
        d->setEncryptionKeys(allowMixed ? UnknownProtocol : preferredSolution.protocol, std::move(preferredSolution.encryptionKeys),
                             allowMixed ? UnknownProtocol : alternativeSolution.protocol, std::move(alternativeSolution.encryptionKeys));
    }
    d->updateWidgets();
    d->updateOkButton();

    const auto size = sizeHint();
    const auto desk = QApplication::desktop()->screenGeometry(this);
    resize(QSize(desk.width() / 3, qMin(size.height(), desk.height() / 2)));
}

Kleo::NewKeyApprovalDialog::~NewKeyApprovalDialog() = default;

KeyResolver::Solution NewKeyApprovalDialog::result()
{
    return d->mAcceptedResult;
}

#include "newkeyapprovaldialog.moc"
