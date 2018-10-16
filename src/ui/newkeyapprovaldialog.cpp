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
    }
};
static std::shared_ptr<KeyFilter> s_pgpFilter = std::shared_ptr<KeyFilter> (new OpenPGPFilter);
class OpenPGPSignFilter: public DefaultKeyFilter
{
public:
    OpenPGPSignFilter() : DefaultKeyFilter()
    {
        /* Also list unusable keys to make it transparent why they are unusable */
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
    }
};
static std::shared_ptr<KeyFilter> s_smimeFilter = std::shared_ptr<KeyFilter> (new SMIMEFilter);
class SMIMESignFilter: public DefaultKeyFilter
{
public:
    SMIMESignFilter(): DefaultKeyFilter()
    {
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
        mFilterBtn(new QPushButton)
    {
        auto hLay = new QHBoxLayout(this);
        hLay->addWidget(combo, 1);
        hLay->addWidget(mFilterBtn, 0);

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

private:
    KeySelectionCombo *mCombo;
    QPushButton *mFilterBtn;
    QString mLastIdFilter;
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
        mScrollLayout->setMargin(0);

        q->setWindowTitle(i18n("Security approval"));

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


        QObject::connect (mFormatBtns, static_cast<void (QButtonGroup::*)(int, bool)> (&QButtonGroup::buttonToggled),
                q, [this](int, bool) {
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
        progress->setWindowTitle(i18n("Key generation"));
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
            combo->setDefaultKey(QString::fromLatin1(result.fingerprint()));
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
        if (mRunningJobs.empty()) {
            q->accept();
        }
    }

    void accepted()
    {
        // We can assume everything was validly resolved, otherwise
        // the OK button would have been disabled.
        // Handle custom items now.
        for (auto combo: mAllCombos) {
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
        for (auto combo: mSigningCombos) {
            combo->setKeyFilter(mCurSigFilter);
        }
        for (auto combo: mEncCombos) {
            combo->setKeyFilter(mCurEncFilter);
        }
    }

    ComboWidget *createSigningCombo(const QString &addr, const GpgME::Key &key)
    {
        auto combo = new KeySelectionCombo();
        combo->setKeyFilter(mCurSigFilter);
        if (!key.isNull()) {
            combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()));
        }
        if (key.isNull() && mProto != GpgME::CMS) {
            combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("document-new")),
                                    i18n("Generate a new key pair"), GenerateKey);
        }
        combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("emblem-unavailable")),
                i18n("Don't confirm identity and integrity"), IgnoreKey);

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
                if (resolved[addr].size() == 1) {
                    comboWidget->combo()->setIdFilter(addr);
                }
                sigLayout->addWidget(comboWidget);
            }
        }
        for (const QString &addr: unresolved) {
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
                combo->setDefaultKey(QString::fromLatin1(key.primaryFingerprint()));
            }

            if (mSender == addr && key.isNull()) {
                combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("document-new")),
                                        i18n("Generate a new key pair"), GenerateKey);
            }

            combo->appendCustomItem(QIcon::fromTheme(QStringLiteral("emblem-unavailable")),
                    i18n("Ignore recipient"), IgnoreKey);

            if (keys.size () == 1) {
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

        mOkButton->setEnabled(!isAllIgnored);

        if (!isGenerate) {
            mOkButton->setText(origOkText);
        }

        if (Formatting::complianceMode() != QStringLiteral("de-vs")) {
            return;
        }

        // Handle compliance
        bool de_vs = true;
        for (const auto &key: q->signingKeys()) {
            if (!Formatting::isKeyDeVs(key) || keyValidity(key) < GpgME::UserID::Validity::Full) {
                de_vs = false;
                break;
            }
        }
        if (de_vs) {
            for (const auto &keys: q->encryptionKeys().values()) {
                for (const auto &key: keys) {
                    if (!Formatting::isKeyDeVs(key) || keyValidity(key) < GpgME::UserID::Validity::Full) {
                        de_vs = false;
                        break;
                    }
                }
                if (!de_vs) {
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
    d->updateOkButton();

    const auto size = sizeHint();
    const auto desk = QApplication::desktop()->screenGeometry(this);
    resize(QSize(desk.width() / 3, qMin(size.height(), desk.height() / 2)));
}

std::vector<GpgME::Key> NewKeyApprovalDialog::signingKeys()
{
    std::vector <GpgME::Key> ret;

    for (const auto combo: d->mSigningCombos) {
        ret.push_back(combo->currentKey());
    }

    return ret;
}

QMap <QString, std::vector<GpgME::Key> > NewKeyApprovalDialog::encryptionKeys()
{
    QMap <QString, std::vector<GpgME::Key> > ret;
    for (const auto combo: d->mEncCombos) {
        const auto &addr = combo->property("address").toString();
        const auto &key = combo->currentKey();
        if (ret.contains(addr)) {
            ret[addr].push_back(key);
        } else {
            std::vector<GpgME::Key> vec;
            vec.push_back(key);
            ret.insert(addr, vec);
        }
    }
    return ret;
}

#include "newkeyapprovaldialog.moc"
