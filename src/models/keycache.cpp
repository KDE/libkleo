/* -*- mode: c++; c-basic-offset:4 -*-
    models/keycache.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2007,2008 Klarälvdalens Datakonsult AB

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

#include "keycache.h"
#include "keycache_p.h"

#include "libkleo_debug.h"

#include "kleo/predicates.h"
#include "kleo/stl_util.h"
#include "kleo/dn.h"
#include "utils/filesystemwatcher.h"

#include <gpgme++/error.h>
#include <gpgme++/key.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/verificationresult.h>
#include <gpgme++/keylistresult.h>

#include <qgpgme/protocol.h>
#include <qgpgme/listallkeysjob.h>

#include <gpg-error.h>

//#include <kmime/kmime_header_parsing.h>


#include <QPointer>
#include <QTimer>
#include <QEventLoop>

#include <utility>
#include <algorithm>
#include <functional>
#include <iterator>

using namespace Kleo;
using namespace GpgME;
using namespace KMime::Types;

static const unsigned int hours2ms = 1000 * 60 * 60;

//
//
// KeyCache
//
//

namespace
{

make_comparator_str(ByEMail, .first.c_str());

}

class KeyCache::Private
{
    friend class ::Kleo::KeyCache;
    KeyCache *const q;
public:
    explicit Private(KeyCache *qq) : q(qq), m_refreshInterval(1), m_initalized(false)
    {
        connect(&m_autoKeyListingTimer, &QTimer::timeout, q, [this]() { q->startKeyListing(); });
        updateAutoKeyListingTimer();
    }

    ~Private()
    {
        if (m_refreshJob) {
            m_refreshJob->cancel();
        }
    }

    template < template <template <typename U> class Op> class Comp>
    std::vector<Key>::const_iterator find(const std::vector<Key> &keys, const char *key) const
    {
        ensureCachePopulated();
        const std::vector<Key>::const_iterator it =
            std::lower_bound(keys.begin(), keys.end(), key, Comp<std::less>());
        if (it == keys.end() || Comp<std::equal_to>()(*it, key)) {
            return it;
        } else {
            return keys.end();
        }
    }

    template < template <template <typename U> class Op> class Comp>
    std::vector<Subkey>::const_iterator find(const std::vector<Subkey> &keys, const char *key) const
    {
        ensureCachePopulated();
        const std::vector<Subkey>::const_iterator it =
            std::lower_bound(keys.begin(), keys.end(), key, Comp<std::less>());
        if (it == keys.end() || Comp<std::equal_to>()(*it, key)) {
            return it;
        } else {
            return keys.end();
        }
    }

    std::vector<Key>::const_iterator find_fpr(const char *fpr) const
    {
        return find<_detail::ByFingerprint>(by.fpr, fpr);
    }

    std::pair< std::vector< std::pair<std::string, Key> >::const_iterator,
        std::vector< std::pair<std::string, Key> >::const_iterator >
        find_email(const char *email) const
    {
        ensureCachePopulated();
        return std::equal_range(by.email.begin(), by.email.end(),
                                email, ByEMail<std::less>());
    }

    std::vector<Key> find_mailbox(const QString &email, bool sign) const;

    std::vector<Subkey>::const_iterator find_subkeyid(const char *subkeyid) const
    {
        return find<_detail::ByKeyID>(by.subkeyid, subkeyid);
    }

    std::vector<Key>::const_iterator find_keyid(const char *keyid) const
    {
        return find<_detail::ByKeyID>(by.keyid, keyid);
    }

    std::vector<Key>::const_iterator find_shortkeyid(const char *shortkeyid) const
    {
        return find<_detail::ByShortKeyID>(by.shortkeyid, shortkeyid);
    }

    std::pair <
    std::vector<Key>::const_iterator,
        std::vector<Key>::const_iterator
        > find_subjects(const char *chain_id) const
    {
        ensureCachePopulated();
        return std::equal_range(by.chainid.begin(), by.chainid.end(),
                                chain_id, _detail::ByChainID<std::less>());
    }

    void refreshJobDone(const KeyListResult &result);

    void setRefreshInterval(int interval)
    {
        m_refreshInterval = interval;
        updateAutoKeyListingTimer();
    }

    int refreshInterval() const
    {
        return m_refreshInterval;
    }

    void updateAutoKeyListingTimer()
    {
        setAutoKeyListingInterval(hours2ms * m_refreshInterval);
    }
    void setAutoKeyListingInterval(int ms)
    {
        m_autoKeyListingTimer.stop();
        m_autoKeyListingTimer.setInterval(ms);
        if (ms != 0) {
            m_autoKeyListingTimer.start();
        }
    }

    void ensureCachePopulated() const;

private:
    QPointer<RefreshKeysJob> m_refreshJob;
    std::vector<std::shared_ptr<FileSystemWatcher> > m_fsWatchers;
    QTimer m_autoKeyListingTimer;
    int m_refreshInterval;

    struct By {
        std::vector<Key> fpr, keyid, shortkeyid, chainid;
        std::vector< std::pair<std::string, Key> > email;
        std::vector<Subkey> subkeyid;
    } by;
    bool m_initalized;
};

std::shared_ptr<const KeyCache> KeyCache::instance()
{
    return mutableInstance();
}

std::shared_ptr<KeyCache> KeyCache::mutableInstance()
{
    static std::weak_ptr<KeyCache> self;
    try {
        return std::shared_ptr<KeyCache>(self);
    } catch (const std::bad_weak_ptr &) {
        const std::shared_ptr<KeyCache> s(new KeyCache);
        self = s;
        return s;
    }
}

KeyCache::KeyCache()
    : QObject(), d(new Private(this))
{

}

KeyCache::~KeyCache() {}

void KeyCache::enableFileSystemWatcher(bool enable)
{
    for (const auto &i : qAsConst(d->m_fsWatchers)) {
        i->setEnabled(enable);
    }
}

void KeyCache::setRefreshInterval(int hours)
{
    d->setRefreshInterval(hours);
}

int KeyCache::refreshInterval() const
{
    return d->refreshInterval();
}

void KeyCache::reload(GpgME::Protocol /*proto*/)
{
    if (d->m_refreshJob) {
        return;
    }

    d->updateAutoKeyListingTimer();

    enableFileSystemWatcher(false);
    d->m_refreshJob = new RefreshKeysJob(this);
    connect(d->m_refreshJob.data(), &RefreshKeysJob::done,
            this, [this](const GpgME::KeyListResult &r) {
                d->refreshJobDone(r);
            });
    d->m_refreshJob->start();
}

void KeyCache::cancelKeyListing()
{
    if (!d->m_refreshJob) {
        return;
    }
    d->m_refreshJob->cancel();
}

void KeyCache::addFileSystemWatcher(const std::shared_ptr<FileSystemWatcher> &watcher)
{
    if (!watcher) {
        return;
    }
    d->m_fsWatchers.push_back(watcher);
    connect(watcher.get(), &FileSystemWatcher::directoryChanged,
            this, [this]() { startKeyListing(); });
    connect(watcher.get(), &FileSystemWatcher::fileChanged,
            this, [this]() { startKeyListing(); });

    watcher->setEnabled(d->m_refreshJob == nullptr);
}

void KeyCache::Private::refreshJobDone(const KeyListResult &result)
{
    q->enableFileSystemWatcher(true);
    m_initalized = true;
    Q_EMIT q->keyListingDone(result);
}

const Key &KeyCache::findByFingerprint(const char *fpr) const
{
    const std::vector<Key>::const_iterator it = d->find_fpr(fpr);
    if (it == d->by.fpr.end()) {
        static const Key null;
        return null;
    } else {
        return *it;
    }
}

const Key &KeyCache::findByFingerprint(const std::string &fpr) const
{
    return findByFingerprint(fpr.c_str());
}

std::vector<Key> KeyCache::findByEMailAddress(const char *email) const
{
    const auto pair = d->find_email(email);
    std::vector<Key> result;
    result.reserve(std::distance(pair.first, pair.second));
    std::transform(pair.first, pair.second,
                   std::back_inserter(result),
                   [](const std::pair<std::string, Key> &pair) {
                       return pair.second;
                   });
    return result;
}

std::vector<Key> KeyCache::findByEMailAddress(const std::string &email) const
{
    return findByEMailAddress(email.c_str());
}

const Key &KeyCache::findByShortKeyID(const char *id) const
{
    const std::vector<Key>::const_iterator it = d->find_shortkeyid(id);
    if (it != d->by.shortkeyid.end()) {
        return *it;
    }
    static const Key null;
    return null;
}

const Key &KeyCache::findByShortKeyID(const std::string &id) const
{
    return findByShortKeyID(id.c_str());
}

const Key &KeyCache::findByKeyIDOrFingerprint(const char *id) const
{
    {
        // try by.fpr first:
        const std::vector<Key>::const_iterator it = d->find_fpr(id);
        if (it != d->by.fpr.end()) {
            return *it;
        }
    }{
        // try by.keyid next:
        const std::vector<Key>::const_iterator it = d->find_keyid(id);
        if (it != d->by.keyid.end()) {
            return *it;
        }
    }
    static const Key null;
    return null;
}

const Key &KeyCache::findByKeyIDOrFingerprint(const std::string &id) const
{
    return findByKeyIDOrFingerprint(id.c_str());
}

std::vector<Key> KeyCache::findByKeyIDOrFingerprint(const std::vector<std::string> &ids) const
{

    std::vector<std::string> keyids;
    std::remove_copy_if(ids.begin(), ids.end(), std::back_inserter(keyids),
                        [](const std::string &str) {
                            return !str.c_str() || !*str.c_str();
                        });

    // this is just case-insensitive string search:
    std::sort(keyids.begin(), keyids.end(), _detail::ByFingerprint<std::less>());

    std::vector<Key> result;
    result.reserve(keyids.size());   // dups shouldn't happen
    d->ensureCachePopulated();

    kdtools::set_intersection(d->by.fpr.begin(), d->by.fpr.end(),
                              keyids.begin(), keyids.end(),
                              std::back_inserter(result),
                              _detail::ByFingerprint<std::less>());
    if (result.size() < keyids.size()) {
        // note that By{Fingerprint,KeyID,ShortKeyID} define the same
        // order for _strings_
        kdtools::set_intersection(d->by.keyid.begin(), d->by.keyid.end(),
                                  keyids.begin(), keyids.end(),
                                  std::back_inserter(result),
                                  _detail::ByKeyID<std::less>());
    }
    // duplicates shouldn't happen, but make sure nonetheless:
    std::sort(result.begin(), result.end(), _detail::ByFingerprint<std::less>());
    result.erase(std::unique(result.begin(), result.end(), _detail::ByFingerprint<std::equal_to>()), result.end());

    // we skip looking into short key ids here, as it's highly
    // unlikely they're used for this purpose. We might need to revise
    // this decision, but only after testing.
    return result;
}

std::vector<Subkey> KeyCache::findSubkeysByKeyID(const std::vector<std::string> &ids) const
{
    std::vector<std::string> sorted;
    sorted.reserve(ids.size());
    std::remove_copy_if(ids.begin(), ids.end(), std::back_inserter(sorted),
                        [](const std::string &str) {
                            return !str.c_str() || !*str.c_str();
                        });

    std::sort(sorted.begin(), sorted.end(), _detail::ByKeyID<std::less>());

    std::vector<Subkey> result;
    d->ensureCachePopulated();
    kdtools::set_intersection(d->by.subkeyid.begin(), d->by.subkeyid.end(),
                              sorted.begin(), sorted.end(),
                              std::back_inserter(result),
                              _detail::ByKeyID<std::less>());
    return result;
}

std::vector<Key> KeyCache::findRecipients(const DecryptionResult &res) const
{
    std::vector<std::string> keyids;
    Q_FOREACH (const DecryptionResult::Recipient &r, res.recipients())
        if (const char *kid = r.keyID()) {
            keyids.push_back(kid);
        }
    const std::vector<Subkey> subkeys = findSubkeysByKeyID(keyids);
    std::vector<Key> result;
    result.reserve(subkeys.size());
    std::transform(subkeys.begin(), subkeys.end(), std::back_inserter(result),
                   std::mem_fn(&Subkey::parent));

    std::sort(result.begin(), result.end(), _detail::ByFingerprint<std::less>());
    result.erase(std::unique(result.begin(), result.end(), _detail::ByFingerprint<std::equal_to>()), result.end());
    return result;
}

std::vector<Key> KeyCache::findSigners(const VerificationResult &res) const
{
    std::vector<std::string> fprs;
    Q_FOREACH (const Signature &s, res.signatures())
        if (const char *fpr = s.fingerprint()) {
            fprs.push_back(fpr);
        }
    return findByKeyIDOrFingerprint(fprs);
}

std::vector<Key> KeyCache::findSigningKeysByMailbox(const QString &mb) const
{
    return d->find_mailbox(mb, true);
}

std::vector<Key> KeyCache::findEncryptionKeysByMailbox(const QString &mb) const
{
    return d->find_mailbox(mb, false);
}

namespace
{
#define DO( op, meth, meth2 ) if ( op key.meth() ) {} else { qDebug( "rejecting for signing: %s: %s", #meth2, key.primaryFingerprint() ); return false; }
#define ACCEPT( meth ) DO( !!, meth, !meth )
#define REJECT( meth ) DO( !, meth, meth )
struct ready_for_signing : std::unary_function<Key, bool> {
    bool operator()(const Key &key) const
    {
#if 1
        ACCEPT(hasSecret);
        ACCEPT(canReallySign);
        REJECT(isRevoked);
        REJECT(isExpired);
        REJECT(isDisabled);
        REJECT(isInvalid);
        return true;
#else
        return key.hasSecret() &&
               key.canReallySign() && !key.isRevoked() && !key.isExpired() && !key.isDisabled() && !key.isInvalid();
#endif
#undef DO
    }
};

struct ready_for_encryption : std::unary_function<Key, bool> {
#define DO( op, meth, meth2 ) if ( op key.meth() ) {} else { qDebug( "rejecting for encrypting: %s: %s", #meth2, key.primaryFingerprint() ); return false; }
    bool operator()(const Key &key) const
    {
#if 1
        ACCEPT(canEncrypt);
        REJECT(isRevoked);
        REJECT(isExpired);
        REJECT(isDisabled);
        REJECT(isInvalid);
        return true;
#else
        return
            key.canEncrypt()    && !key.isRevoked() && !key.isExpired() && !key.isDisabled() && !key.isInvalid();
#endif
    }
#undef DO
#undef ACCEPT
#undef REJECT
};
}

std::vector<Key> KeyCache::Private::find_mailbox(const QString &email, bool sign) const
{
    if (email.isEmpty()) {
        return std::vector<Key>();
    }

    const auto pair = find_email(email.toUtf8().constData());
    std::vector<Key> result;
    result.reserve(std::distance(pair.first, pair.second));
    if (sign)
        kdtools::copy_2nd_if(pair.first, pair.second,
                             std::back_inserter(result),
                             ready_for_signing());
    else
        kdtools::copy_2nd_if(pair.first, pair.second,
                             std::back_inserter(result),
                             ready_for_encryption());

    return result;
}

std::vector<Key> KeyCache::findSubjects(const GpgME::Key &key, Options options) const
{
    return findSubjects(std::vector<Key>(1, key), options);
}

std::vector<Key> KeyCache::findSubjects(const std::vector<Key> &keys, Options options) const
{
    return findSubjects(keys.begin(), keys.end(), options);
}

std::vector<Key> KeyCache::findSubjects(std::vector<Key>::const_iterator first, std::vector<Key>::const_iterator last, Options options) const
{

    if (first == last) {
        return std::vector<Key>();
    }

    std::vector<Key> result;
    while (first != last) {
        const auto pair = d->find_subjects(first->primaryFingerprint());
        result.insert(result.end(), pair.first, pair.second);
        ++first;
    }

    std::sort(result.begin(), result.end(), _detail::ByFingerprint<std::less>());
    result.erase(std::unique(result.begin(), result.end(), _detail::ByFingerprint<std::equal_to>()), result.end());

    if (options & RecursiveSearch) {
        const std::vector<Key> furtherSubjects = findSubjects(result, options);
        std::vector<Key> combined;
        combined.reserve(result.size() + furtherSubjects.size());
        std::merge(result.begin(), result.end(),
                   furtherSubjects.begin(), furtherSubjects.end(),
                   std::back_inserter(combined),
                   _detail::ByFingerprint<std::less>());
        combined.erase(std::unique(combined.begin(), combined.end(), _detail::ByFingerprint<std::equal_to>()), combined.end());
        result.swap(combined);
    }

    return result;
}

std::vector<Key> KeyCache::findIssuers(const Key &key, Options options) const
{

    if (key.isNull()) {
        return std::vector<Key>();
    }

    std::vector<Key> result;
    if (options & IncludeSubject) {
        result.push_back(key);
    }

    if (key.isRoot()) {
        return result;
    }

    const Key &issuer = findByFingerprint(key.chainID());

    if (issuer.isNull()) {
        return result;
    }

    result.push_back(issuer);

    if (!(options & RecursiveSearch)) {
        return result;
    }

    while (!result.back().isNull() && !result.back().isRoot()) {
        result.push_back(findByFingerprint(result.back().chainID()));
    }

    if (result.back().isNull()) {
        result.pop_back();
    }

    return result;
}

std::vector<Key> KeyCache::findIssuers(const std::vector<Key> &keys, Options options) const
{
    return findIssuers(keys.begin(), keys.end(), options);
}

std::vector<Key> KeyCache::findIssuers(std::vector<Key>::const_iterator first, std::vector<Key>::const_iterator last, Options options) const
{

    if (first == last) {
        return std::vector<Key>();
    }

    // extract chain-ids, identifying issuers:
    std::vector<const char *> chainIDs;
    chainIDs.reserve(last - first);
    kdtools::transform_if(first, last, std::back_inserter(chainIDs),
                          std::mem_fn(&Key::chainID),
                          [](const Key &key) { return !key.isRoot(); });
    std::sort(chainIDs.begin(), chainIDs.end(), _detail::ByFingerprint<std::less>());

    const auto lastUniqueChainID = std::unique(chainIDs.begin(), chainIDs.end(), _detail::ByFingerprint<std::less>());

    std::vector<Key> result;
    result.reserve(lastUniqueChainID - chainIDs.begin());

    d->ensureCachePopulated();

    kdtools::set_intersection(d->by.fpr.begin(), d->by.fpr.end(),
                              chainIDs.begin(), lastUniqueChainID,
                              std::back_inserter(result),
                              _detail::ByFingerprint<std::less>());

    if (options & IncludeSubject) {
        const unsigned int rs = result.size();
        result.insert(result.end(), first, last);
        std::inplace_merge(result.begin(), result.begin() + rs, result.end(),
                           _detail::ByFingerprint<std::less>());
    }

    if (!(options & RecursiveSearch)) {
        return result;
    }

    const std::vector<Key> l2result = findIssuers(result, options & ~IncludeSubject);

    const unsigned long result_size = result.size();
    result.insert(result.end(), l2result.begin(), l2result.end());
    std::inplace_merge(result.begin(), result.begin() + result_size, result.end(),
                       _detail::ByFingerprint<std::less>());
    return result;
}

static std::string email(const UserID &uid)
{
    const std::string email = uid.email();
    if (email.empty()) {
        return DN(uid.id())[QStringLiteral("EMAIL")].trimmed().toUtf8().constData();
    }
    if (email[0] == '<' && email[email.size() - 1] == '>') {
        return email.substr(1, email.size() - 2);
    } else {
        return email;
    }
}

static std::vector<std::string> emails(const Key &key)
{
    std::vector<std::string> emails;
    Q_FOREACH (const UserID &uid, key.userIDs()) {
        const std::string e = email(uid);
        if (!e.empty()) {
            emails.push_back(e);
        }
    }
    std::sort(emails.begin(), emails.end(), ByEMail<std::less>());
    emails.erase(std::unique(emails.begin(), emails.end(), ByEMail<std::equal_to>()), emails.end());
    return emails;
}

void KeyCache::remove(const Key &key)
{
    if (key.isNull()) {
        return;
    }

    const char *fpr = key.primaryFingerprint();
    if (!fpr) {
        return;
    }

    Q_EMIT aboutToRemove(key);

    {
        const auto range = std::equal_range(d->by.fpr.begin(), d->by.fpr.end(), fpr,
                                            _detail::ByFingerprint<std::less>());
        d->by.fpr.erase(range.first, range.second);
    }

    if (const char *keyid = key.keyID()) {
        const auto range = std::equal_range(d->by.keyid.begin(), d->by.keyid.end(), keyid,
                                            _detail::ByKeyID<std::less>());
        const auto it = std::remove_if(range.first, range.second,
                                       [fpr](const GpgME::Key &key) {
                                           return _detail::ByFingerprint<std::equal_to>()(fpr, key);
                                       });
        d->by.keyid.erase(it, range.second);
    }

    if (const char *shortkeyid = key.shortKeyID()) {
        const auto range = std::equal_range(d->by.shortkeyid.begin(), d->by.shortkeyid.end(), shortkeyid,
                                            _detail::ByShortKeyID<std::less>());
        const auto it = std::remove_if(range.first, range.second,
                                       [fpr](const GpgME::Key &key) {
                                           return _detail::ByFingerprint<std::equal_to>()(fpr, key);
                                       });
        d->by.shortkeyid.erase(it, range.second);
    }

    if (const char *chainid = key.chainID()) {
        const auto range = std::equal_range(d->by.chainid.begin(), d->by.chainid.end(), chainid,
                                            _detail::ByChainID<std::less>());
        const auto range2 = std::equal_range(range.first, range.second, fpr, _detail::ByFingerprint<std::less>());
        d->by.chainid.erase(range2.first, range2.second);
    }

    Q_FOREACH (const std::string &email, emails(key)) {
        const auto range = std::equal_range(d->by.email.begin(), d->by.email.end(), email, ByEMail<std::less>());
        const auto it = std::remove_if(range.first, range.second,
                                       [fpr](const std::pair<std::string, Key> &pair) {
                                           return qstricmp(fpr, pair.second.primaryFingerprint()) == 0;
                                       });
        d->by.email.erase(it, range.second);
    }

    Q_FOREACH (const Subkey &subkey, key.subkeys()) {
        if (const char *keyid = subkey.keyID()) {
            const auto range = std::equal_range(d->by.subkeyid.begin(), d->by.subkeyid.end(), keyid,
                                                _detail::ByKeyID<std::less>());
            const auto range2 = std::equal_range(range.first, range.second, fpr, _detail::ByKeyID<std::less>());
            d->by.subkeyid.erase(range2.first, range2.second);
        }
    }
}

void KeyCache::remove(const std::vector<Key> &keys)
{
    for (const Key &key : keys) {
        remove(key);
    }
}

const std::vector<GpgME::Key> &KeyCache::keys() const
{
    d->ensureCachePopulated();
    return d->by.fpr;
}

std::vector<Key> KeyCache::secretKeys() const
{
    std::vector<Key> keys = this->keys();
    keys.erase(std::remove_if(keys.begin(), keys.end(),
                              [](const Key &key) { return !key.hasSecret(); }),
               keys.end());
    return keys;
}

void KeyCache::refresh(const std::vector<Key> &keys)
{
    // make this better...
    clear();
    insert(keys);
}

void KeyCache::insert(const Key &key)
{
    insert(std::vector<Key>(1, key));
}

namespace
{

template <
    template <template <typename T> class Op> class T1,
    template <template <typename T> class Op> class T2
    > struct lexicographically
{
    typedef bool result_type;

    template <typename U, typename V>
    bool operator()(const U &lhs, const V &rhs) const
    {
        return
            T1<std::less>()(lhs, rhs) ||
            (T1<std::equal_to>()(lhs, rhs) &&
             T2<std::less>()(lhs, rhs))
            ;
    }
};

}

void KeyCache::insert(const std::vector<Key> &keys)
{

    // 1. remove those with empty fingerprints:
    std::vector<Key> sorted;
    sorted.reserve(keys.size());
    std::remove_copy_if(keys.begin(), keys.end(),
                        std::back_inserter(sorted),
                        [](const Key &key) {
                            auto fp = key.primaryFingerprint();
                            return !fp|| !*fp;
                        });

    Q_FOREACH (const Key &key, sorted) {
        remove(key);    // this is sub-optimal, but makes implementation from here on much easier
    }

    // 2. sort by fingerprint:
    std::sort(sorted.begin(), sorted.end(), _detail::ByFingerprint<std::less>());

    // 2a. insert into fpr index:
    std::vector<Key> by_fpr;
    by_fpr.reserve(sorted.size() + d->by.fpr.size());
    std::merge(sorted.begin(), sorted.end(),
               d->by.fpr.begin(), d->by.fpr.end(),
               std::back_inserter(by_fpr),
               _detail::ByFingerprint<std::less>());

    // 3. build email index:
    std::vector< std::pair<std::string, Key> > pairs;
    pairs.reserve(sorted.size());
    Q_FOREACH (const Key &key, sorted) {
        const std::vector<std::string> emails = ::emails(key);
        for (const std::string &e : emails) {
            pairs.push_back(std::make_pair(e, key));
        }
    }
    std::sort(pairs.begin(), pairs.end(), ByEMail<std::less>());

    // 3a. insert into email index:
    std::vector< std::pair<std::string, Key> > by_email;
    by_email.reserve(pairs.size() + d->by.email.size());
    std::merge(pairs.begin(), pairs.end(),
               d->by.email.begin(), d->by.email.end(),
               std::back_inserter(by_email),
               ByEMail<std::less>());

    // 3.5: stable-sort by chain-id (effectively lexicographically<ByChainID,ByFingerprint>)
    std::stable_sort(sorted.begin(), sorted.end(), _detail::ByChainID<std::less>());

    // 3.5a: insert into chain-id index:
    std::vector<Key> nonroot;
    nonroot.reserve(sorted.size());
    std::vector<Key> by_chainid;
    by_chainid.reserve(sorted.size() + d->by.chainid.size());
    std::copy_if(sorted.cbegin(), sorted.cend(),
                 std::back_inserter(nonroot),
                 [](const Key &key) { return !key.isRoot(); });
    std::merge(nonroot.cbegin(), nonroot.cend(),
               d->by.chainid.cbegin(), d->by.chainid.cend(),
               std::back_inserter(by_chainid),
               lexicographically<_detail::ByChainID, _detail::ByFingerprint>());

    // 4. sort by key id:
    std::sort(sorted.begin(), sorted.end(), _detail::ByKeyID<std::less>());

    // 4a. insert into keyid index:
    std::vector<Key> by_keyid;
    by_keyid.reserve(sorted.size() + d->by.keyid.size());
    std::merge(sorted.begin(), sorted.end(),
               d->by.keyid.begin(), d->by.keyid.end(),
               std::back_inserter(by_keyid),
               _detail::ByKeyID<std::less>());

    // 5. sort by short key id:
    std::sort(sorted.begin(), sorted.end(), _detail::ByShortKeyID<std::less>());

    // 5a. insert into short keyid index:
    std::vector<Key> by_shortkeyid;
    by_shortkeyid.reserve(sorted.size() + d->by.shortkeyid.size());
    std::merge(sorted.begin(), sorted.end(),
               d->by.shortkeyid.begin(), d->by.shortkeyid.end(),
               std::back_inserter(by_shortkeyid),
               _detail::ByShortKeyID<std::less>());

    // 6. build subkey ID index:
    std::vector<Subkey> subkeys;
    subkeys.reserve(sorted.size());
    Q_FOREACH (const Key &key, sorted)
        Q_FOREACH (const Subkey &subkey, key.subkeys()) {
            subkeys.push_back(subkey);
        }

    // 6a sort by key id:
    std::sort(subkeys.begin(), subkeys.end(), _detail::ByKeyID<std::less>());

    // 6b. insert into subkey ID index:
    std::vector<Subkey> by_subkeyid;
    by_email.reserve(subkeys.size() + d->by.subkeyid.size());
    std::merge(subkeys.begin(), subkeys.end(),
               d->by.subkeyid.begin(), d->by.subkeyid.end(),
               std::back_inserter(by_subkeyid),
               _detail::ByKeyID<std::less>());

    // now commit (well, we already removed keys...)
    by_fpr.swap(d->by.fpr);
    by_keyid.swap(d->by.keyid);
    by_shortkeyid.swap(d->by.shortkeyid);
    by_email.swap(d->by.email);
    by_subkeyid.swap(d->by.subkeyid);
    by_chainid.swap(d->by.chainid);

    for (const Key &key : qAsConst(sorted)) {
        Q_EMIT added(key);
    }

    Q_EMIT keysMayHaveChanged();
}

void KeyCache::clear()
{
    d->by = Private::By();
}

//
//
// RefreshKeysJob
//
//

class KeyCache::RefreshKeysJob::Private
{
    RefreshKeysJob *const q;
public:
    Private(KeyCache *cache, RefreshKeysJob *qq);
    void doStart();
    Error startKeyListing(GpgME::Protocol protocol);
    void listAllKeysJobDone(const KeyListResult &res, const std::vector<Key> &nextKeys)
    {
        std::vector<Key> keys;
        keys.reserve(m_keys.size() + nextKeys.size());
        if (m_keys.empty()) {
            keys = nextKeys;
        } else
            std::merge(m_keys.begin(), m_keys.end(),
                       nextKeys.begin(), nextKeys.end(),
                       std::back_inserter(keys),
                       _detail::ByFingerprint<std::less>());
        m_keys.swap(keys);
        jobDone(res);
    }
    void emitDone(const KeyListResult &result);
    void updateKeyCache();

    QPointer<KeyCache> m_cache;
    QVector<QGpgME::ListAllKeysJob*> m_jobsPending;
    std::vector<Key> m_keys;
    KeyListResult m_mergedResult;
    bool m_canceled;

private:
    void jobDone(const KeyListResult &res);
};

KeyCache::RefreshKeysJob::Private::Private(KeyCache *cache, RefreshKeysJob *qq)
    : q(qq)
    , m_cache(cache)
    , m_canceled(false)
{
    Q_ASSERT(m_cache);
}

void KeyCache::RefreshKeysJob::Private::jobDone(const KeyListResult &result)
{
    if (m_canceled) {
        q->deleteLater();
        return;
    }

    QObject *const sender = q->sender();
    if (sender) {
        sender->disconnect(q);
    }
    Q_ASSERT(m_jobsPending.size() > 0);
    m_jobsPending.removeOne(qobject_cast<QGpgME::ListAllKeysJob*>(sender));
    m_mergedResult.mergeWith(result);
    if (m_jobsPending.size() > 0) {
        return;
    }
    updateKeyCache();
    emitDone(m_mergedResult);
}

void KeyCache::RefreshKeysJob::Private::emitDone(const KeyListResult &res)
{
    q->deleteLater();
    Q_EMIT q->done(res);
}

KeyCache::RefreshKeysJob::RefreshKeysJob(KeyCache *cache, QObject *parent) : QObject(parent), d(new Private(cache, this))
{
}

KeyCache::RefreshKeysJob::~RefreshKeysJob() {}

void KeyCache::RefreshKeysJob::start()
{
    QTimer::singleShot(0, this, [this](){ d->doStart(); });
}

void KeyCache::RefreshKeysJob::cancel()
{
    d->m_canceled = true;
    std::for_each(d->m_jobsPending.begin(), d->m_jobsPending.end(),
                  std::mem_fn(&QGpgME::ListAllKeysJob::slotCancel));
    Q_EMIT canceled();
}

void KeyCache::RefreshKeysJob::Private::doStart()
{
    if (m_canceled) {
        q->deleteLater();
        return;
    }

    Q_ASSERT(m_jobsPending.size() == 0);
    m_mergedResult.mergeWith(KeyListResult(startKeyListing(GpgME::OpenPGP)));
    m_mergedResult.mergeWith(KeyListResult(startKeyListing(GpgME::CMS)));

    if (m_jobsPending.size() != 0) {
        return;
    }

    const bool hasError = m_mergedResult.error() || m_mergedResult.error().isCanceled();
    emitDone(hasError ? m_mergedResult : KeyListResult(Error(GPG_ERR_UNSUPPORTED_OPERATION)));
}

void KeyCache::RefreshKeysJob::Private::updateKeyCache()
{
    if (!m_cache || m_canceled) {
        q->deleteLater();
        return;
    }

    std::vector<Key> cachedKeys = m_cache->initialized() ? m_cache->keys() : std::vector<Key>();
    std::sort(cachedKeys.begin(), cachedKeys.end(), _detail::ByFingerprint<std::less>());
    std::vector<Key> keysToRemove;
    std::set_difference(cachedKeys.begin(), cachedKeys.end(),
                        m_keys.begin(), m_keys.end(),
                        std::back_inserter(keysToRemove),
                        _detail::ByFingerprint<std::less>());
    m_cache->remove(keysToRemove);
    m_cache->refresh(m_keys);
}

Error KeyCache::RefreshKeysJob::Private::startKeyListing(GpgME::Protocol proto)
{
    const auto * const protocol = (proto == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    if (!protocol) {
        return Error();
    }
    QGpgME::ListAllKeysJob *const job = protocol->listAllKeysJob(/*includeSigs*/false, /*validate*/true);
    if (!job) {
        return Error();
    }

#if 0
    aheinecke: 2017.01.12:

    For unkown reasons the new style connect fails at runtime
    over library borders into QGpgME from the GpgME repo
    when cross compiled for Windows and default arguments
    are used in the Signal.

    This was tested with gcc 4.9 (Mingw 3.0.2) and we could not
    find an explanation for this. So until this is fixed or we understand
    the problem we need to use the old style connect for QGpgME signals.

    The new style connect of the canceled signal right below
    works fine.

    connect(job, &QGpgME::ListAllKeysJob::result,
            q, [this](const GpgME::KeyListResult &res, const std::vector<GpgME::Key> &keys) {
                listAllKeysJobDone(res, keys);
            });
#endif
    connect(job, SIGNAL(result(GpgME::KeyListResult,std::vector<GpgME::Key>)),
            q, SLOT(listAllKeysJobDone(GpgME::KeyListResult,std::vector<GpgME::Key>)));

    connect(q, &RefreshKeysJob::canceled, job, &QGpgME::Job::slotCancel);

    const Error error = job->start(true);

    if (!error && !error.isCanceled()) {
        m_jobsPending.push_back(job);
    }
    return error;
}

bool KeyCache::initialized() const
{
    return d->m_initalized;
}

void KeyCache::Private::ensureCachePopulated() const
{
    if (!m_initalized) {
        q->startKeyListing();
        QEventLoop loop;
        loop.connect(q, &KeyCache::keyListingDone,
                     &loop, &QEventLoop::quit);
        qCDebug(LIBKLEO_LOG) << "Waiting for keycache.";
        loop.exec();
        qCDebug(LIBKLEO_LOG) << "Keycache available.";
    }
}

#include "moc_keycache_p.cpp"
#include "moc_keycache.cpp"

