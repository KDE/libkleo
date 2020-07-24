/*  -*- c++ -*-
    newkeyapprovaldialog.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2018 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "newkeyapprovaldialog.h"
#include "kleo/defaultkeyfilter.h"
#include "keyselectioncombo.h"
#include "progressdialog.h"
#include "utils/formatting.h"


#include "libkleo_debug.h"

#include <QApplication>
#include <QButtonGroup>
#include <QDesktopWidget>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QLabel>
#include <QMap>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QToolTip>
#include <QVBoxLayout>

#include <QGpgME/DefaultKeyGenerationJob>
#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>
#include <gpgme++/keygenerationresult.h>
#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>

using namespace Kleo;

namespace {
class OpenPGPFilter: public DefaultKeyFilter
{
public:
    OpenPGPFilter() : DefaultKeyFilter()
    {
        setIsOpenPGP(DefaultKeyFilter::Set);
        setCanEncrypt(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_pgpFilter = std::shared_ptr<KeyFilter> (new OpenPGPFilter);
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
static std::shared_ptr<KeyFilter> s_smimeFilter = std::shared_ptr<KeyFilter> (new SMIMEFilter);
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
static std::shared_ptr<KeyFilter> s_defaultFilter= std::shared_ptr<KeyFilter> (new DefaultKeyFilter);
class SignFilter: public DefaultKeyFilter
{
public:
    SignFilter(): DefaultKeyFilter()
    {
        setHasSecret(DefaultKeyFilter::Set);
    }
};
static std::shared_ptr<KeyFilter> s_signFilter = std::shared_ptr<KeyFilter> (new SignFilter);

/* Some decoration and a button to remove the filter for a keyselectioncombo */
class ComboWidget: public QWidget
{
    Q_OBJECT
public:
    explicit ComboWidget(KeySelectionCombo *combo):
        mCombo(combo),
        mFilterBtn(new QPushButton),
        mFromOverride(GpgME::UnknownProtocol)
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

        // Assume that combos start out with a filter
        mFilterBtn->setIcon(QIcon::fromTheme(QStringLiteral("kt-remove-filters")));
        mFilterBtn->setToolTip(i18n("Remove Filter"));

        // FIXME: This is ugly to enforce but otherwise the
        // icon is broken.
        combo->setMinimumHeight(22);
        mFilterBtn->setMinimumHeight(23);

        connect(mFilterBtn, &QPushButton::clicked, this, [this] () {
            const QString curFilter = mCombo->idFilter();
            if (curFilter.isEmpty()) {
                mCombo->setIdFilter(mLastIdFilter);
                mLastIdFilter = QString();
                mFilterBtn->setIcon(QIcon::fromTheme(QStringLiteral("kt-remove-filters")));
                mFilterBtn->setToolTip(i18n("Remove Filter"));
            } else {
                mLastIdFilter = curFilter;
                mFilterBtn->setIcon(QIcon::fromTheme(QStringLiteral("kt-add-filters")));
                mFilterBtn->setToolTip(i18n("Add Filter"));
                mCombo->setIdFilter(QString());
            }
        });
    }

    KeySelectionCombo *combo()
    {
        return mCombo;
    }

    GpgME::Protocol fromOverride() const
    {
        return mFromOverride;
    }

    void setFromOverride(GpgME::Protocol proto)
    {
        mFromOverride = proto;
    }

private:
    KeySelectionCombo *mCombo;
    QPushButton *mFilterBtn;
    QString mLastIdFilter;
    GpgME::Protocol mFromOverride;
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
    Private(NewKeyApprovalDialog *pub,
            GpgME::Protocol forcedProtocol,
            GpgME::Protocol presetProtocol,
            const QString &sender, bool allowMixed):
        mProto(forcedProtocol),
        mSender(sender),
        mAllowMixed(allowMixed),
        q(pub)
    {
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
        mFormatBtns = new QButtonGroup;
        auto pgpBtn = new QRadioButton(i18n("OpenPGP"));
        auto smimeBtn = new QRadioButton(i18n("S/MIME"));
        mFormatBtns->addButton(pgpBtn, 1);
        mFormatBtns->addButton(smimeBtn, 2);
        mFormatBtns->setExclusive(true);

        fmtLayout->addStretch(-1);
        fmtLayout->addWidget(pgpBtn);
        fmtLayout->addWidget(smimeBtn);
        mMainLay->addLayout(fmtLayout);

        // Handle force / preset
        if (forcedProtocol == GpgME::OpenPGP) {
            pgpBtn->setChecked(true);
            pgpBtn->setVisible(false);
            smimeBtn->setVisible(false);
        } else if (forcedProtocol == GpgME::CMS) {
            smimeBtn->setChecked(true);
            pgpBtn->setVisible(false);
            smimeBtn->setVisible(false);
        } else if (presetProtocol == GpgME::CMS) {
            smimeBtn->setChecked(true);
        } else if (!mAllowMixed) {
            pgpBtn->setChecked(true);
        } else if (mAllowMixed) {
            smimeBtn->setVisible(false);
            pgpBtn->setVisible(false);
        }

        updateFilter();


        QObject::connect (mFormatBtns, static_cast<void (QButtonGroup::*)(QAbstractButton *, bool)> (&QButtonGroup::buttonToggled),
                q, [this](QAbstractButton *, bool) {
            updateFilter();
        });

        mMainLay->addWidget(mScrollArea);

        mComplianceLbl = new QLabel;
        mComplianceLbl->setVisible(false);

        auto btnLayout = new QHBoxLayout;
        btnLayout->addWidget(mComplianceLbl);
        btnLayout->addWidget(btnBox);
        mMainLay->addLayout(btnLayout);

        q->setLayout(mMainLay);

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
        bool isPGP = mFormatBtns->checkedId() == 1;
        bool isSMIME = mFormatBtns->checkedId() == 2;

        mAcceptedEnc.clear();
        mAcceptedSig.clear();

        for (const auto combo: qAsConst(mEncCombos)) {
            const auto &addr = combo->property("address").toString();
            const auto &key = combo->currentKey();
            if (!combo->isVisible()) {
                continue;
            }
            if (isSMIME && key.protocol() != GpgME::CMS) {
                continue;
            }
            if (isPGP && key.protocol() != GpgME::OpenPGP) {
                continue;
            }
            if (mAcceptedEnc.contains(addr)) {
                mAcceptedEnc[addr].push_back(key);
            } else {
                std::vector<GpgME::Key> vec;
                vec.push_back(key);
                mAcceptedEnc.insert(addr, vec);
            }
        }
        for (const auto combo: qAsConst(mSigningCombos)) {
            const auto key = combo->currentKey();
            if (!combo->isVisible()) {
                continue;
            }
            if (isSMIME && key.protocol() != GpgME::CMS) {
                continue;
            }
            if (isPGP && key.protocol() != GpgME::OpenPGP) {
                continue;
            }
            mAcceptedSig.push_back(combo->currentKey());
        }

        q->accept();
    }

    void accepted()
    {
        // We can assume everything was validly resolved, otherwise
        // the OK button would have been disabled.
        // Handle custom items now.
        for (auto combo: qAsConst(mAllCombos)) {
            auto act = combo->currentData(Qt::UserRole).toInt();
            if (act == GenerateKey) {
                generateKey(combo);
                // Only generate once
                return;
            }
        }
        checkAccepted();
    }

    void updateFilter()
    {
        bool isPGP = mFormatBtns->checkedId() == 1;
        bool isSMIME = mFormatBtns->checkedId() == 2;

        if (isSMIME) {
            mCurEncFilter = s_smimeFilter;
            mCurSigFilter = s_smimeSignFilter;
        } else if (isPGP) {
            mCurEncFilter = s_pgpFilter;
            mCurSigFilter = s_pgpSignFilter;
        } else {
            mCurEncFilter = s_defaultFilter;
            mCurSigFilter = s_signFilter;
        }
        for (auto combo: qAsConst(mSigningCombos)) {
            combo->setKeyFilter(mCurSigFilter);
            auto widget = qobject_cast <ComboWidget *>(combo->parentWidget());
            if (!widget) {
                qCDebug(LIBKLEO_LOG) << "Failed to find signature combo widget";
                continue;
            }
            widget->setVisible(widget->fromOverride() == GpgME::UnknownProtocol ||
                               ((isSMIME && widget->fromOverride() == GpgME::CMS) ||
                                (isPGP && widget->fromOverride() == GpgME::OpenPGP)));
        }
        for (auto combo: qAsConst(mEncCombos)) {
            combo->setKeyFilter(mCurEncFilter);

            auto widget = qobject_cast <ComboWidget *>(combo->parentWidget());
            if (!widget) {
                qCDebug(LIBKLEO_LOG) << "Failed to find combo widget";
                continue;
            }
            widget->setVisible(widget->fromOverride() == GpgME::UnknownProtocol ||
                               ((isSMIME && widget->fromOverride() == GpgME::CMS) ||
                                (isPGP && widget->fromOverride() == GpgME::OpenPGP)));
        }
    }

    ComboWidget *createSigningCombo(const QString &addr, const GpgME::Key &key)
    {
        auto combo = new KeySelectionCombo();
        combo->setKeyFilter(mCurSigFilter);
        if (!key.isNull()) {
            combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()), key.protocol());
        }
        if (key.isNull() && mProto != GpgME::CMS) {
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

        return new ComboWidget(combo);
    }

    void addSigningKeys(const QMap<QString, std::vector<GpgME::Key> > &resolved,
                        const QStringList &unresolved)
    {
        if (resolved.empty() && unresolved.empty()) {
            return;
        }
        for (const QString &addr: resolved.keys()) {
            auto group = new QGroupBox(i18nc("Caption for signing key selection",
                                             "Confirm identity '%1' as:", addr));
            group->setAlignment(Qt::AlignLeft);
            mScrollLayout->addWidget(group);
            auto sigLayout = new QVBoxLayout;

            group->setLayout(sigLayout);
            for (const auto &key: resolved[addr])
            {
                auto comboWidget = createSigningCombo(addr, key);
                if (key_has_addr (key, addr)) {
                    comboWidget->combo()->setIdFilter(addr);
                }
                if (resolved[addr].size() > 1) {
                    comboWidget->setFromOverride(key.protocol());
                }
                sigLayout->addWidget(comboWidget);
            }
        }
        for (const QString &addr: qAsConst(unresolved)) {
            auto group = new QGroupBox(i18nc("Caption for signing key selection, no key found",
                                             "No key found for the address '%1':", addr));
            group->setAlignment(Qt::AlignLeft);
            mScrollLayout->addWidget(group);
            auto sigLayout = new QHBoxLayout;

            group->setLayout(sigLayout);

            auto comboWidget = createSigningCombo(addr, GpgME::Key());
            comboWidget->combo()->setIdFilter(addr);
            sigLayout->addWidget(comboWidget);
        }
    }

    void addEncryptionAddr(const QString &addr, const std::vector<GpgME::Key> &keys,
                           QGridLayout *encGrid)
    {
        encGrid->addWidget(new QLabel(addr), encGrid->rowCount(), 0);
        for (const auto &key: keys)
        {
            auto combo = new KeySelectionCombo(false);
            combo->setKeyFilter(mCurEncFilter);
            if (!key.isNull()) {
                combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()),
                                     key.protocol());
            }

            if (mSender == addr && key.isNull()) {
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

            if (key.isNull() || key_has_addr (key, addr)) {
                combo->setIdFilter(addr);
            }

            connect(combo, &KeySelectionCombo::currentKeyChanged, q, [this] () {
                updateOkButton();
            });
            connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), q, [this] () {
                updateOkButton();
            });

            mEncCombos << combo;
            mAllCombos << combo;
            combo->setProperty("address", addr);
            auto comboWidget = new ComboWidget(combo);
            if (keys.size() > 1) {
                comboWidget->setFromOverride(key.protocol());
            }
            encGrid->addWidget(comboWidget, encGrid->rowCount(), 0, 1, 2);
        }
    }

    void addEncryptionKeys(const QMap<QString, std::vector<GpgME::Key> > &resolved,
                           const QStringList &unresolved)
    {
        if (resolved.empty() && unresolved.empty()) {
            return;
        }
        auto group = new QGroupBox(i18n("Encrypt to:"));
        group->setAlignment(Qt::AlignLeft);
        auto encGrid = new QGridLayout;
        group->setLayout(encGrid);
        mScrollLayout->addWidget(group);

        for (const QString &addr: resolved.keys()) {
            addEncryptionAddr(addr, resolved[addr], encGrid);
        }
        std::vector<GpgME::Key> dummy;
        dummy.push_back(GpgME::Key());
        for (const QString &addr: unresolved) {
            addEncryptionAddr(addr, dummy, encGrid);
        }

        encGrid->setColumnStretch(1, -1);
        mScrollLayout->addStretch(-1);
    }

    void updateOkButton()
    {
        static QString origOkText = mOkButton->text();
        bool isGenerate = false;
        bool isAllIgnored = true;
        // Check if generate is selected.
        for (auto combo: mAllCombos) {
            auto act = combo->currentData(Qt::UserRole).toInt();
            if (act == GenerateKey) {
                mOkButton->setText(i18n("Generate"));
                isGenerate = true;
            }
            if (act != IgnoreKey) {
                isAllIgnored = false;
            }
        }

        // If we don't encrypt the ok button is always enabled. But otherwise
        // we only enable it if we encrypt to at least one recipient.
        if (!mEncCombos.size()) {
            mOkButton->setEnabled(true);
        } else {
            mOkButton->setEnabled(!isAllIgnored);
        }

        if (!isGenerate) {
            mOkButton->setText(origOkText);
        }

        if (Formatting::complianceMode() != QLatin1String("de-vs")) {
            return;
        }

        // Handle compliance
        bool de_vs = true;

        bool isPGP = mFormatBtns->checkedId() == 1;
        bool isSMIME = mFormatBtns->checkedId() == 2;

        for (const auto combo: qAsConst(mEncCombos)) {
            const auto &key = combo->currentKey();
            if (!combo->isVisible()) {
                continue;
            }
            if (isSMIME && key.protocol() != GpgME::CMS) {
                continue;
            }
            if (isPGP && key.protocol() != GpgME::OpenPGP) {
                continue;
            }
            if (!Formatting::isKeyDeVs(key) || keyValidity(key) < GpgME::UserID::Validity::Full) {
                de_vs = false;
                break;
            }
        }
        if (de_vs) {
            for (const auto combo: qAsConst(mSigningCombos)) {
                const auto key = combo->currentKey();
                if (!combo->isVisible()) {
                    continue;
                }
                if (isSMIME && key.protocol() != GpgME::CMS) {
                    continue;
                }
                if (isPGP && key.protocol() != GpgME::OpenPGP) {
                    continue;
                }
                if (!Formatting::isKeyDeVs(key) || keyValidity(key) < GpgME::UserID::Validity::Full) {
                    de_vs = false;
                    break;
                }
            }
        }

        mOkButton->setIcon(QIcon::fromTheme(de_vs
                    ? QStringLiteral("security-high")
                    : QStringLiteral("security-medium")));
        mOkButton->setStyleSheet(QStringLiteral("background-color: ") + (de_vs
                    ? QStringLiteral("#D5FAE2")  // KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::PositiveBackground).color().name()
                    : QStringLiteral("#FAE9EB"))); //KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NegativeBackground).color().name()));
        mComplianceLbl->setText(de_vs
                ? i18nc("VS-NfD-conforming is a German standard for restricted documents for which special restrictions about algorithms apply.  The string states that all cryptographic operations necessary for the communication are compliant with that.",
                    "VS-NfD-compliant communication possible.")
                : i18nc("VS-NfD-conforming is a German standard for restricted documents for which special restrictions about algorithms apply.  The string states that all cryptographic operations necessary for the communication are compliant with that.",
                    "VS-NfD-compliant communication not possible."));
        mComplianceLbl->setVisible(true);
    }

    void selectionChanged()
    {
        bool isPGP = false;
        bool isCMS = false;
        for (const auto combo: mEncCombos) {
            isPGP |= combo->currentKey().protocol() == GpgME::OpenPGP;
            isCMS |= combo->currentKey().protocol() == GpgME::CMS;
            if (isPGP && isCMS) {
                break;
            }
        }
    }

    ~Private() {}

    GpgME::Protocol mProto;
    QList<KeySelectionCombo *> mSigningCombos;
    QList<KeySelectionCombo *> mEncCombos;
    QList<KeySelectionCombo *> mAllCombos;
    QScrollArea *mScrollArea;
    QVBoxLayout *mScrollLayout;
    QPushButton *mOkButton;
    QVBoxLayout *mMainLay;
    QButtonGroup *mFormatBtns;
    std::shared_ptr<KeyFilter> mCurSigFilter;
    std::shared_ptr<KeyFilter> mCurEncFilter;
    QString mSender;
    bool mAllowMixed;
    NewKeyApprovalDialog *q;
    QList <QGpgME::Job *> mRunningJobs;
    GpgME::Error mLastError;
    QLabel *mComplianceLbl;
    QMap<QString, std::vector<GpgME::Key> > mAcceptedEnc;
    std::vector<GpgME::Key> mAcceptedSig;
    QString mGenerateTooltip;
};

NewKeyApprovalDialog::NewKeyApprovalDialog(const QMap<QString, std::vector<GpgME::Key> > &resolvedSigningKeys,
                                           const QMap<QString, std::vector<GpgME::Key> > &resolvedRecp,
                                           const QStringList &unresolvedSigKeys,
                                           const QStringList &unresolvedRecp,
                                           const QString &sender,
                                           bool allowMixed,
                                           GpgME::Protocol forcedProtocol,
                                           GpgME::Protocol presetProtocol,
                                           QWidget *parent,
                                           Qt::WindowFlags f): QDialog(parent, f),
                                                             d(new Private(this, forcedProtocol, presetProtocol, sender, allowMixed))
{
    d->addSigningKeys(resolvedSigningKeys, unresolvedSigKeys);
    d->addEncryptionKeys(resolvedRecp, unresolvedRecp);
    d->updateFilter();
    d->updateOkButton();

    const auto size = sizeHint();
    const auto desk = QApplication::desktop()->screenGeometry(this);
    resize(QSize(desk.width() / 3, qMin(size.height(), desk.height() / 2)));
}

std::vector<GpgME::Key> NewKeyApprovalDialog::signingKeys()
{
    return d->mAcceptedSig;
}

QMap <QString, std::vector<GpgME::Key> > NewKeyApprovalDialog::encryptionKeys()
{
    return d->mAcceptedEnc;
}

#include "newkeyapprovaldialog.moc"
