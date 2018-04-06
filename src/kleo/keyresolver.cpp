/*  -*- c++ -*-
    keyresolver.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2018 Intevation GmbH

    Based on kpgp.cpp
    Copyright (C) 2001,2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

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

#include <gpgme++/key.h>

#include "libkleo_debug.h"
#include "keyresolver.h"
#include "models/keycache.h"

#include "ui/newkeyapprovaldialog.h"

#include <QStringList>

using namespace Kleo;

namespace {

static inline bool ValidEncryptionKey(const GpgME::Key &key)
{
    if (key.isRevoked() || key.isExpired() || key.isDisabled() || !key.canEncrypt()) {
        return false;
    }
    return true;
}

static inline bool ValidEncryptionKeyForValidity(const GpgME::Key &key, const QString &address,
                                                 int minimumValidity)
{
    if (!ValidEncryptionKey(key)) {
        return false;
    }
    for (const auto &uid: key.userIDs()) {
        if (uid.addrSpec() == address.toStdString()) {
            if (uid.validity() >= minimumValidity) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

class KeyResolver::Private
{
public:
    Private(KeyResolver* qq, bool enc, bool sig, CryptoMessageFormat fmt, bool allowMixed) :
            q(qq), mFormat(fmt), mEncrypt(enc), mSign(sig), mNag(true),
            mAllowMixed(allowMixed),
            mCache(KeyCache::instance()),
            mDialogWindowFlags(Qt::WindowFlags()),
            mMinimumValidty(GpgME::UserID::Marginal)
    {
    }

    ~Private()
    {
    }

    void addRecpients (const QStringList &addresses, bool hidden)
    {
        if (!mEncrypt) {
            return;
        }

        // Internally we work with normalized addresses. Normalisation
        // matches the gnupg one.
        for (const auto &addr :addresses) {
            // PGP Uids are defined to be UTF-8 (RFC 4880 §5.11)
            const auto normalized = GpgME::UserID::addrSpecFromString (addr.toUtf8().constData());
            if (normalized.empty()) {
                // should not happen bug in the caller, non localized
                // error for bug reporting.
                mFatalErrors << QStringLiteral("The mail address for '%1' could not be extracted").arg(addr);
                continue;
            }
            const QString normStr = QString::fromUtf8(normalized.c_str());

            // Initially mark them as unresolved for both protocols
            if (!mUnresolvedCMS.contains(normStr)) {
                mUnresolvedCMS << normStr;
            }
            if (!mUnresolvedPGP.contains(normStr)) {
                mUnresolvedPGP << normStr;
            }

            // Add it to the according recipient lists
            if (hidden) {
                mHiddenRecipients << normStr;
            } else {
                mRecipients << normStr;
            }
        }
    }

    // Apply the overrides this is also where specific formats come in
    void resolveOverrides()
    {
        if (!mEncrypt) {
            // No encryption we are done.
            return;
        }
        for (CryptoMessageFormat fmt: mOverrides.keys()) {
            // Iterate over the crypto message formats
            if (mFormat != AutoFormat && mFormat != fmt) {
                // Skip overrides for the wrong format
                continue;
            }
            for (const auto addr: mOverrides[fmt].keys()) {
                // For all adress overrides of this format.
                for (const auto fprOrId: mOverrides[fmt][addr]) {
                    // For all the keys configured for this address.
                    const auto key = mCache->findByKeyIDOrFingerprint(fprOrId.toUtf8().constData());
                    if (key.isNull()) {
                        qCDebug (LIBKLEO_LOG) << "Failed to find override key for:" << addr
                            << "fpr:" << fprOrId;
                        continue;
                    }

                    // Now add it to the resolved keys and remove it from our list
                    // of unsresolved keys.
                    QMap<CryptoMessageFormat, QMap <QString, std::vector<GpgME::Key> > > *targetMap;
                    if (mRecipients.contains(addr)) {
                        targetMap = &mEncKeys;
                    } else if (mHiddenRecipients.contains(addr)) {
                        targetMap = &mBccKeys;
                    } else {
                        qCWarning(LIBKLEO_LOG) << "Override provided for an address that is "
                            "neither sender nor recipient. Address: " << addr;
                        continue;
                    }

                    auto recpMap = targetMap->value(fmt);
                    auto keys = recpMap.value(addr);
                    keys.push_back(key);
                    recpMap.insert(addr, keys);
                    targetMap->insert(fmt, recpMap);

                    // Now we can remove it from our unresolved lists.
                    if (key.protocol() == GpgME::OpenPGP) {
                        mUnresolvedPGP.removeAll(addr);
                    } else {
                        mUnresolvedCMS.removeAll(addr);
                    }
                }
            }
        }
    }

    void resolveSign(GpgME::Protocol proto)
    {
        auto fmt = proto == GpgME::OpenPGP ? AnyOpenPGP : AnySMIME;
        if (mSigKeys.contains(fmt)) {
            // Explicitly set
            return;
        }
        const auto keys = mCache->findBestByMailBox(mSender.toUtf8().constData(),
                                                    proto, true, false);
        if (!keys.empty() && !keys[0].isNull()) {
            mSigKeys.insert(fmt, keys);
        }
    }

    void setSigningKeys(const std::vector<GpgME::Key> keys)
    {
        if (mSign) {
            for (const auto &key: keys) {
                const auto sigFmt = key.protocol() == GpgME::Protocol::OpenPGP ? AnyOpenPGP : AnySMIME;
                auto list = mSigKeys.value(sigFmt);
                list.push_back(key);
                mSigKeys.insert(sigFmt, list);
            }
        }
    }

    // Try to find matching keys in the provided protocol for the unresolved addresses
    // only updates the any maps.
    void resolveEnc(GpgME::Protocol proto)
    {
        auto fmt = proto == GpgME::OpenPGP ? AnyOpenPGP : AnySMIME;
        auto encMap = mEncKeys.value(fmt);
        auto hiddenMap = mBccKeys.value(fmt);
        QMutableStringListIterator it((proto == GpgME::Protocol::OpenPGP) ? mUnresolvedPGP : mUnresolvedCMS);
        while (it.hasNext()) {
            const QString addr = it.next();
            const auto keys = mCache->findBestByMailBox(addr.toUtf8().constData(),
                                                        proto, false, true);
            if (keys.empty() || keys[0].isNull()) {
                qCDebug(LIBKLEO_LOG) << "Failed to find any"
                                     << (proto == GpgME::Protocol::OpenPGP ? "OpenPGP" : "CMS")
                                     << "key for: " << addr;
                continue;
            }
            if (keys.size() == 1) {
                // Otherwise we have a group key and don't need to
                // check.
                if (!ValidEncryptionKeyForValidity(keys[0], addr, mMinimumValidty)) {
                    qCDebug(LIBKLEO_LOG) << "key for: " << addr << keys[0].primaryFingerprint() <<
                        "has not enough validity";
                    continue;
                }
            }
            if (mHiddenRecipients.contains(addr)) {
                hiddenMap.insert(addr, keys);
            } else {
                encMap.insert(addr, keys);
                for (const auto &k: keys) {
                    if (!k.isNull()) {
                        qCDebug(LIBKLEO_LOG) << "Resolved encrypt to" << addr
                                             << "with key" << k.primaryFingerprint();
                    }
                }
            }
            it.remove();
        }
        mEncKeys.insert(fmt, encMap);
        mBccKeys.insert(fmt, hiddenMap);
    }

    void encMapToSpecific(CryptoMessageFormat anyFormat, CryptoMessageFormat specificFormat,
                          QMap<CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > >&encMap)
    {
        Q_ASSERT(anyFormat & specificFormat);
        if (!encMap.contains(anyFormat)) {
            return;
        }
        for (const auto &addr: encMap[anyFormat].keys()) {
            if (!encMap.contains(specificFormat)) {
                encMap.insert(specificFormat, QMap<QString, std::vector<GpgME::Key> >());
            }
            encMap[specificFormat].insert(addr, encMap[anyFormat][addr]);
        }
        encMap.remove(anyFormat);
    }

    void reduceToSingle(CryptoMessageFormat targetFmt)
    {
        // We a have a specific format so we need to map any keys
        // into that format. This ignores overrides as the format
        // was explicitly set.
        CryptoMessageFormat srcFmt = (targetFmt & AnySMIME) ? AnySMIME : AnyOpenPGP;
        if (mSigKeys.contains(srcFmt)) {
            mSigKeys.insert(targetFmt, mSigKeys.take(srcFmt));
        }
        encMapToSpecific(srcFmt, targetFmt, mEncKeys);
        encMapToSpecific(srcFmt, targetFmt, mBccKeys);
    }

    void updateEncMap(QMap<QString, std::vector<GpgME::Key> > &target,
                      QMap<QString, std::vector<GpgME::Key> > &src)
    {
        for (const auto &addr: target.keys()) {
            if (src.contains(addr)) {
                target.insert(addr, src[addr]);
            }
        }
    }

    void updateEncMaps(CryptoMessageFormat target, CryptoMessageFormat src)
    {
        if (mBccKeys.contains(src) && mBccKeys.contains(target)) {
            updateEncMap(mBccKeys[target], mBccKeys[src]);
        }
        if (mEncKeys.contains(src) && mEncKeys.contains(target)) {
            updateEncMap(mEncKeys[target], mEncKeys[src]);
        }
    }

    bool needsFormat(CryptoMessageFormat fmt)
    {
        return mBccKeys.contains(fmt) || mEncKeys.contains(fmt);
    }

    void selectFormats()
    {
        // Check if we can find a single common specific format that works
        if (mFormat != AutoFormat && mFormat != AnyOpenPGP && mFormat != AnySMIME) {
            reduceToSingle(mFormat);
        }

        // OpenPGP
        // By default prefer OpenPGPMIME
        bool needTwoPGP = needsFormat(OpenPGPMIMEFormat) && needsFormat(InlineOpenPGPFormat);
        reduceToSingle(OpenPGPMIMEFormat);
        if (needTwoPGP) {
            // We need two messages as we have conflicting preferences.

            // Then we need to check that if we sign the PGP MIME Message we
            // also sign the inline one.
            if (mSigKeys.contains(OpenPGPMIMEFormat)) {
                mSigKeys.insert(InlineOpenPGPFormat,
                                mSigKeys[OpenPGPMIMEFormat]);
            }

            // Then it's also possible that a user updated a key in the
            // UI so we need to check that too.
            updateEncMaps(InlineOpenPGPFormat, OpenPGPMIMEFormat);
        }

        // Similar for S/MIME
        bool needTwoSMIME = needsFormat(SMIMEOpaqueFormat) && needsFormat(SMIMEFormat);
        // Here we prefer real S/MIME
        reduceToSingle(SMIMEFormat);
        if (needTwoSMIME) {
            if (mSigKeys.contains(SMIMEFormat)) {
                mSigKeys.insert(SMIMEOpaqueFormat,
                                mSigKeys[SMIMEFormat]);
            }
            updateEncMaps(SMIMEOpaqueFormat, SMIMEFormat);
        }
        return;
    }

    void showApprovalDialog(QWidget *parent)
    {
        QMap<QString, std::vector<GpgME::Key> > resolvedSig;
        QStringList unresolvedSig;
        bool pgpOnly = mUnresolvedPGP.empty() && (!mSign || mSigKeys.contains(AnyOpenPGP));
        bool cmsOnly = mUnresolvedCMS.empty() && (!mSign || mSigKeys.contains(AnySMIME));
        // First handle the signing keys
        if (mSign) {
            if (mSigKeys.empty()) {
                unresolvedSig << mSender;
            } else {
                std::vector<GpgME::Key> resolvedSigKeys;
                for (const auto &keys: mSigKeys) {
                    for (const auto &key: keys) {
                        if ((pgpOnly && key.protocol() != GpgME::OpenPGP) ||
                            (cmsOnly && key.protocol() != GpgME::CMS)) {
                            continue;
                        }
                        resolvedSigKeys.push_back(key);
                    }
                }
                resolvedSig.insert(mSender, resolvedSigKeys);
            }
        }

        // Now build the encryption keys
        QMap<QString, std::vector<GpgME::Key> > resolvedRecp;
        QStringList unresolvedRecp;

        if (mEncrypt) {
            // Use all unresolved recpients.
            if (!cmsOnly && !pgpOnly) {
                if (mFormat & AutoFormat) {
                    // In Auto Format we can now remove recpients that could
                    // be resolved either through CMS or PGP
                    for (const auto &addr: mUnresolvedPGP) {
                        if (mUnresolvedCMS.contains(addr)) {
                            unresolvedRecp << addr;
                        }
                    }
                } else if (mFormat & AnyOpenPGP) {
                    unresolvedRecp = mUnresolvedPGP;
                } else if (mFormat & AnySMIME) {
                    unresolvedRecp = mUnresolvedCMS;
                }
            }

            // Now Map all resolved encryption keys regardless of the format.
            for (const auto &map: mEncKeys.values()) {
                // Foreach format
                for (const auto &addr: map.keys()) {
                    // Foreach sender
                    if (!resolvedRecp.contains(addr) || !resolvedRecp[addr].size()) {
                        resolvedRecp.insert(addr, map[addr]);
                    } else {
                        for (const auto &k: map[addr]) {
                            resolvedRecp[addr].push_back(k);
                        }
                    }
                }
            }
        }

        // Do we force the protocol?
        GpgME::Protocol forcedProto = mFormat == AutoFormat ? GpgME::UnknownProtocol :
                                      mFormat & AnyOpenPGP ? GpgME::OpenPGP :
                                      GpgME::CMS;

        // Start with the protocol for which every keys could be found.
        GpgME::Protocol presetProtocol = pgpOnly ? GpgME::OpenPGP :
                                         cmsOnly ? GpgME::CMS :
                                         GpgME::UnknownProtocol;

        mDialog = std::shared_ptr<NewKeyApprovalDialog>(new NewKeyApprovalDialog(resolvedSig,
                                                                                 resolvedRecp,
                                                                                 unresolvedSig,
                                                                                 unresolvedRecp,
                                                                                 mSender,
                                                                                 mAllowMixed,
                                                                                 forcedProto,
                                                                                 presetProtocol,
                                                                                 parent,
                                                                                 mDialogWindowFlags));
        connect (mDialog.get(), &QDialog::accepted, q, [this] () {
            dialogAccepted();
        });
        connect (mDialog.get(), &QDialog::rejected, q, [this] () {
            Q_EMIT q->keysResolved(false, false);}
        );
        mDialog->open();
    }

    void dialogAccepted()
    {
        // Update keymaps accordingly
        mSigKeys.clear();
        for (const auto &key: mDialog->signingKeys()) {
            CryptoMessageFormat fmt = key.protocol() == GpgME::OpenPGP ? AnyOpenPGP : AnySMIME;
            if (!mSigKeys.contains(fmt)) {
                mSigKeys.insert(fmt, std::vector<GpgME::Key>());
            }
            mSigKeys[fmt].push_back(key);
        }
        const auto &encMap = mDialog->encryptionKeys();
        // First we clear the Any Maps and fill them with
        // the results of the dialog. Then we use the sender
        // address to determine if a keys in the specific
        // maps need updating.
        mEncKeys.remove(AnyOpenPGP);
        mEncKeys.remove(AnySMIME);
        mBccKeys.remove(AnyOpenPGP);
        mBccKeys.remove(AnySMIME);

        bool isUnresolved = false;
        for (const auto &addr: encMap.keys()) {
            for (const auto &key: encMap[addr]) {
                if (key.isNull()) {
                    isUnresolved = true;
                }
                CryptoMessageFormat fmt = key.protocol() == GpgME::OpenPGP ? AnyOpenPGP : AnySMIME;
                // Should we add to hidden or normal?
                QMap<CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > > *targetMap =
                    mHiddenRecipients.contains(addr) ? &mBccKeys : &mEncKeys;
                if (!targetMap->contains(fmt)) {
                    targetMap->insert(fmt, QMap<QString, std::vector<GpgME::Key> >());
                }

                if (!(*targetMap)[fmt].contains(addr)) {
                    (*targetMap)[fmt].insert(addr, std::vector<GpgME::Key>());
                }
                (*targetMap)[fmt][addr].push_back(key);
            }
        }

        if (isUnresolved) {
            // TODO show warning
        }

        Q_EMIT q->keysResolved(true, false);
    }

    KeyResolver *q;
    QString mSender;
    QStringList mRecipients;
    QStringList mHiddenRecipients;
    QMap<CryptoMessageFormat, std::vector<GpgME::Key> > mSigKeys;
    QMap<CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > >mEncKeys;
    QMap<CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > >mBccKeys;
    QMap<CryptoMessageFormat, QMap<QString, QStringList> > mOverrides;

    QStringList mUnresolvedPGP, mUnresolvedCMS;

    CryptoMessageFormat mFormat;
    QStringList mFatalErrors;
    bool mEncrypt, mSign, mNag;
    bool mAllowMixed;
    // The cache is needed as a member variable to avoid rebuilding
    // it beteween calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
    std::shared_ptr<NewKeyApprovalDialog> mDialog;
    Qt::WindowFlags mDialogWindowFlags;
    int mMinimumValidty;
};

void KeyResolver::start(bool showApproval, QWidget *parentWidget)
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!d->mSign && !d->mEncrypt) {
        // nothing to do
        return Q_EMIT keysResolved(true, true);
    }

    // First resolve through overrides
    d->resolveOverrides();

    // Then look for signing / encryption keys
    if (d->mFormat & AnyOpenPGP) {
        d->resolveSign(GpgME::OpenPGP);
        d->resolveEnc(GpgME::OpenPGP);
    }
    bool pgpOnly = d->mUnresolvedPGP.empty() && (!d->mSign || d->mSigKeys.contains(AnyOpenPGP));

    if (d->mFormat & AnySMIME && (d->mFormat != AutoFormat && pgpOnly)) {
        d->resolveSign(GpgME::CMS);
        d->resolveEnc(GpgME::CMS);
    }
    bool cmsOnly = d->mUnresolvedCMS.empty() && (!d->mSign || d->mSigKeys.contains(AnySMIME));

    // Check if we need the user to select different keys.
    bool needsUser = false;
    if (!pgpOnly && !cmsOnly) {
        for (const auto &unresolved: d->mUnresolvedPGP) {
            if (d->mUnresolvedCMS.contains(unresolved)) {
                // We have at least one unresolvable key.
                needsUser = true;
                break;
            }
        }
        if (d->mSign) {
            // So every recipient could be resolved through
            // a combination of PGP and S/MIME do we also
            // have signining keys for both?
            needsUser |= !(d->mSigKeys.contains(AnyOpenPGP) &&
                           d->mSigKeys.contains(AnySMIME));
        }
    }

    if (!needsUser && !showApproval) {
        d->selectFormats();
        qCDebug(LIBKLEO_LOG) << "Automatic key resolution done.";
        Q_EMIT keysResolved(true, false);
        return;
    } else if (!needsUser) {
        qCDebug(LIBKLEO_LOG) << "No need for the user showing approval anyway.";
    }

    d->showApprovalDialog(parentWidget);
}

KeyResolver::KeyResolver(bool encrypt, bool sign, CryptoMessageFormat fmt, bool allowMixed) :
    d(new Private(this, encrypt, sign, fmt, allowMixed))
{
}

void KeyResolver::setRecipients(const QStringList &addresses)
{
    d->addRecpients(addresses, false);
}

void KeyResolver::setSender(const QString &address)
{
    const auto normalized = GpgME::UserID::addrSpecFromString (address.toUtf8().constData());
    if (normalized.empty()) {
        // should not happen bug in the caller, non localized
        // error for bug reporting.
        d->mFatalErrors << QStringLiteral("The sender address '%1' could not be extracted").arg(address);
        return;
    }
    const auto normStr = QString::fromUtf8(normalized.c_str());
    if (d->mSign) {
        d->mSender = normStr;
    }
    if (d->mEncrypt) {
        if (!d->mUnresolvedCMS.contains(normStr)) {
            d->mUnresolvedCMS << normStr;
        }
        if (!d->mUnresolvedPGP.contains(normStr)) {
            d->mUnresolvedPGP << normStr;
        }
    }
}

void KeyResolver::setHiddenRecipients(const QStringList &addresses)
{
    d->addRecpients(addresses, true);
}

void KeyResolver::setOverrideKeys(const QMap<CryptoMessageFormat, QMap<QString, QStringList> > &overrides)
{
    QMap<QString, QStringList> normalizedOverrides;
    for (const auto fmt: overrides.keys()) {
        for (const auto &addr: overrides[fmt].keys()) {
            const auto normalized = QString::fromUtf8(
                    GpgME::UserID::addrSpecFromString (addr.toUtf8().constData()).c_str());
            const auto fingerprints = overrides[fmt][addr];
            normalizedOverrides.insert(addr, fingerprints);
        }
        d->mOverrides.insert(fmt, normalizedOverrides);
    }
}

QMap <CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > > KeyResolver::encryptionKeys() const
{
    return d->mEncKeys;
}

QMap <CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > > KeyResolver::hiddenKeys() const
{
    return d->mBccKeys;
}

QMap <CryptoMessageFormat, std::vector<GpgME::Key> > KeyResolver::signingKeys() const
{
    return d->mSigKeys;
}

QMap <CryptoMessageFormat, QMap<QString, QStringList> > KeyResolver::overrideKeys() const
{
    return d->mOverrides;
}

void KeyResolver::enableNagging(bool value)
{
    d->mNag = value;
}

void KeyResolver::setDialogWindowFlags(Qt::WindowFlags flags)
{
    d->mDialogWindowFlags = flags;
}

void KeyResolver::setMinimumValidity(int validity)
{
    d->mMinimumValidty = validity;
}
