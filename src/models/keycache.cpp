/* -*- mode: c++; c-basic-offset:4 -*-
    models/keycache.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keycache.h"
#include "keycache_p.h"

#include "kleo/enum.h"
#include "kleo/keygroup.h"
#include "kleo/predicates.h"
#include "kleo/stl_util.h"
#include "kleo/dn.h"

#include "utils/compat.h"
#include "utils/filesystemwatcher.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <gpgme++/error.h>
#include <gpgme++/context.h>
#include <gpgme++/key.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/verificationresult.h>
#include <gpgme++/keylistresult.h>

#include <qgpgme/protocol.h>
#include <qgpgme/listallkeysjob.h>
#include <qgpgme/cryptoconfig.h>

#include <gpg-error.h>

//#include <kmime/kmime_header_parsing.h>


#include <QPointer>
#include <QTimer>
#include <QEventLoop>

#include <utility>
#include <algorithm>
#include <functional>
#include <iterator>

#include "kleo/debug.h"
#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;
using namespace KMime::Types;

static const unsigned int hours2ms = 1000 * 60 * 60;

static const QString groupNamePrefix = QStringLiteral("Group-");

//
//
// KeyCache
//
//

namespace
{

make_comparator_str(ByEMail, .first.c_str());

QStringList getFingerprints(const KeyGroup::Keys &keys)
{
    QStringList fingerprints;
    fingerprints.reserve(keys.size());
    std::transform(keys.cbegin(), keys.cend(),
                    std::back_inserter(fingerprints),
                    [] (const Key &key) {
                        return QString::fromLatin1(key.primaryFingerprint());
                    });
    return fingerprints;
}

}

class KeyCache::Private
{
    friend class ::Kleo::KeyCache;
    KeyCache *const q;
public:
    explicit Private(KeyCache *qq) : q(qq), m_refreshInterval(1), m_initalized(false), m_pgpOnly(true), m_remarks_enabled(false)
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
        const auto it =
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
        const auto it =
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

    std::vector<Subkey>::const_iterator find_keygrip(const char *keygrip) const
    {
        return find<_detail::ByKeyGrip>(by.keygrip, keygrip);
    }

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

    std::vector<Key> getKeysForGroup(const QStringList &fingerprints) const
    {
        std::vector<Key> groupKeys;
        groupKeys.reserve(fingerprints.size());
        for (const QString &fpr : fingerprints) {
            const Key key = q->findByFingerprint(fpr.toLatin1().constData());
            if (key.isNull()) {
                qCDebug (LIBKLEO_LOG) << "Ignoring unknown key with fingerprint:" << fpr;
                continue;
            }
            groupKeys.push_back(key);
        }
        return groupKeys;
    }

    void readGroupsFromGpgConf()
    {
        // According to Werner Koch groups are more of a hack to solve
        // a valid usecase (e.g. several keys defined for an internal mailing list)
        // that won't make it in the proper keylist interface. And using gpgconf
        // was the suggested way to support groups.
        auto conf = QGpgME::cryptoConfig();
        if (!conf) {
            return;
        }

        auto entry = getCryptoConfigEntry(conf, "gpg", "group");
        if (!entry) {
            return;
        }

        // collect the key fingerprints for all groups read from the configuration
        QMap<QString, QStringList> fingerprints;
        const auto stringValueList = entry->stringValueList();
        for (const QString &value: stringValueList) {
            const QStringList split = value.split(QLatin1Char('='));
            if (split.size() != 2) {
                qCDebug (LIBKLEO_LOG) << "Ignoring invalid group config:" << value;
                continue;
            }
            const QString groupName = split[0];
            const QString fingerprint = split[1];
            fingerprints[groupName].push_back(fingerprint);
        }

        // add all groups read from the configuration to the list of groups
        for (auto it = fingerprints.cbegin(); it != fingerprints.cend(); ++it) {
            const QString groupName = it.key();
            const std::vector<Key> groupKeys = getKeysForGroup(it.value());
            KeyGroup g(groupName, groupName, groupKeys, KeyGroup::GnuPGConfig);
            m_groups.push_back(g);
        }
    }

    KeyGroup readGroupFromGroupsConfig(const QString &groupId) const
    {
        Q_ASSERT(!m_groupsConfigName.isEmpty());

        KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(m_groupsConfigName);
        const KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + groupId);

        const QString groupName = configGroup.readEntry("Name", QString());
        const QStringList fingerprints = configGroup.readEntry("Keys", QStringList());
        const std::vector<Key> groupKeys = getKeysForGroup(fingerprints);

        // treat group as immutable if any of its entries is immutable
        const QStringList entries = configGroup.keyList();
        const bool isImmutable = configGroup.isImmutable() || std::any_of(entries.begin(), entries.end(),
                                                                          [configGroup] (const QString &entry) {
                                                                              return configGroup.isEntryImmutable(entry);
                                                                          });

        KeyGroup g(groupId, groupName, groupKeys, KeyGroup::ApplicationConfig);
        g.setIsImmutable(isImmutable);
        qCDebug(LIBKLEO_LOG) << "Read group" << g;

        return g;
    }

    void readGroupsFromGroupsConfig()
    {
        if (m_groupsConfigName.isEmpty()) {
            qCDebug(LIBKLEO_LOG) << "readGroupsFromGroupsConfig - name of application configuration file is unset";
            return;
        }

        const KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(m_groupsConfigName);
        const QStringList configGroups = groupsConfig->groupList();
        for (const QString &configGroupName : configGroups) {
            qCDebug(LIBKLEO_LOG) << "Reading config group" << configGroupName;
            if (configGroupName.startsWith(groupNamePrefix)) {
                const QString keyGroupId = configGroupName.mid(groupNamePrefix.size());
                if (keyGroupId.isEmpty()) {
                    qCWarning(LIBKLEO_LOG) << "Config group" << configGroupName << "has empty group id";
                    continue;
                }
                KeyGroup group = readGroupFromGroupsConfig(keyGroupId);
                m_groups.push_back(group);
            }
        }
    }

    KeyGroup writeGroupToGroupsConfig(const KeyGroup &group)
    {
        if (m_groupsConfigName.isEmpty()) {
            qCDebug(LIBKLEO_LOG) << "writeGroupToGroupsConfig - name of application configuration file is unset";
            return KeyGroup();
        }

        Q_ASSERT(!group.isNull());
        Q_ASSERT(group.source() == KeyGroup::ApplicationConfig);
        if (group.isNull() || group.source() != KeyGroup::ApplicationConfig) {
            qCDebug(LIBKLEO_LOG) << "writeGroupToGroupsConfig - group cannot be written to application configuration:" << group;
            return KeyGroup();
        }

        KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(m_groupsConfigName);
        KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + group.id());

        qCDebug(LIBKLEO_LOG) << "Writing config group" << configGroup.name();
        configGroup.writeEntry("Name", group.name());
        configGroup.writeEntry("Keys", getFingerprints(group.keys()));

        // reread group to ensure that it reflects the saved group in case of immutable entries
        return readGroupFromGroupsConfig(group.id());
    }

    bool removeGroupFromGroupsConfig(const KeyGroup &group)
    {
        if (m_groupsConfigName.isEmpty()) {
            qCDebug(LIBKLEO_LOG) << "removeGroupFromGroupsConfig - name of application configuration file is unset";
            return false;
        }

        Q_ASSERT(!group.isNull());
        Q_ASSERT(group.source() == KeyGroup::ApplicationConfig);
        if (group.isNull() || group.source() != KeyGroup::ApplicationConfig) {
            qCDebug(LIBKLEO_LOG) << "removeGroupFromGroupsConfig - group cannot be removed from application configuration:" << group;
            return false;
        }

        KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(m_groupsConfigName);
        KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + group.id());

        qCDebug(LIBKLEO_LOG) << "Removing config group" << configGroup.name();
        configGroup.deleteGroup();

        return true;
    }

    void updateGroupCache()
    {
        // Update Group Keys
        // this is a quick thing as it only involves reading the config
        // so no need for a job.

        m_groups.clear();
        if (m_groupsEnabled) {
            readGroupsFromGpgConf();
            readGroupsFromGroupsConfig();
        }
    }

    bool insert(const KeyGroup &group)
    {
        Q_ASSERT(!group.isNull());
        Q_ASSERT(group.source() == KeyGroup::ApplicationConfig);
        if (group.isNull() || group.source() != KeyGroup::ApplicationConfig) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::insert - Invalid group:" << group;
            return false;
        }
        const auto it = std::find_if(m_groups.cbegin(), m_groups.cend(),
                                    [group] (const auto &g) {
                                        return g.source() == group.source() && g.id() == group.id();
                                    });
        if (it != m_groups.cend()) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::insert - Group already present in list of groups:" << group;
            return false;
        }

        const KeyGroup savedGroup = writeGroupToGroupsConfig(group);
        if (savedGroup.isNull()) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::insert - Writing group" << group.id() << "to config file failed";
            return false;
        }

        m_groups.push_back(savedGroup);

        Q_EMIT q->groupAdded(savedGroup);

        return true;
    }

    bool update(const KeyGroup &group)
    {
        Q_ASSERT(!group.isNull());
        Q_ASSERT(group.source() == KeyGroup::ApplicationConfig);
        if (group.isNull() || group.source() != KeyGroup::ApplicationConfig) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::update - Invalid group:" << group;
            return false;
        }
        const auto it = std::find_if(m_groups.cbegin(), m_groups.cend(),
                                    [group] (const auto &g) {
                                        return g.source() == group.source() && g.id() == group.id();
                                    });
        if (it == m_groups.cend()) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::update - Group not found in list of groups:" << group;
            return false;
        }
        const auto groupIndex = std::distance(m_groups.cbegin(), it);

        const KeyGroup savedGroup = writeGroupToGroupsConfig(group);
        if (savedGroup.isNull()) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::update - Writing group" << group.id() << "to config file failed";
            return false;
        }

        m_groups[groupIndex] = savedGroup;

        Q_EMIT q->groupUpdated(savedGroup);

        return true;
    }

    bool remove(const KeyGroup &group)
    {
        Q_ASSERT(!group.isNull());
        Q_ASSERT(group.source() == KeyGroup::ApplicationConfig);
        if (group.isNull() || group.source() != KeyGroup::ApplicationConfig) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::remove - Invalid group:" << group;
            return false;
        }
        const auto it = std::find_if(m_groups.cbegin(), m_groups.cend(),
                                    [group] (const auto &g) {
                                        return g.source() == group.source() && g.id() == group.id();
                                    });
        if (it == m_groups.cend()) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::remove - Group not found in list of groups:" << group;
            return false;
        }

        const bool success = removeGroupFromGroupsConfig(group);
        if (!success) {
            qCDebug(LIBKLEO_LOG) << "KeyCache::Private::remove - Removing group" << group.id() << "from config file failed";
            return false;
        }

        m_groups.erase(it);

        Q_EMIT q->groupRemoved(group);

        return true;
    }

private:
    QPointer<RefreshKeysJob> m_refreshJob;
    std::vector<std::shared_ptr<FileSystemWatcher> > m_fsWatchers;
    QTimer m_autoKeyListingTimer;
    int m_refreshInterval;

    struct By {
        std::vector<Key> fpr, keyid, shortkeyid, chainid;
        std::vector< std::pair<std::string, Key> > email;
        std::vector<Subkey> subkeyid, keygrip;
    } by;
    bool m_initalized;
    bool m_pgpOnly;
    bool m_remarks_enabled;
    bool m_groupsEnabled = false;
    QString m_groupsConfigName;
    std::vector<KeyGroup> m_groups;
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

void KeyCache::setGroupsEnabled(bool enabled)
{
    d->m_groupsEnabled = enabled;
    if (d->m_initalized) {
        d->updateGroupCache();
    }
}

void KeyCache::setGroupsConfig(const QString &filename)
{
    d->m_groupsConfigName = filename;
}

void KeyCache::enableFileSystemWatcher(bool enable)
{
    for (const auto &i : std::as_const(d->m_fsWatchers)) {
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

    watcher->setEnabled(d->m_refreshJob.isNull());
}

void KeyCache::enableRemarks(bool value)
{
    if (!d->m_remarks_enabled && value) {
        d->m_remarks_enabled = value;
        if (d->m_initalized && !d->m_refreshJob) {
            qCDebug(LIBKLEO_LOG) << "Reloading keycache with remarks enabled";
            reload();
        } else {
            connect(d->m_refreshJob.data(), &RefreshKeysJob::done,
                    this, [this](const GpgME::KeyListResult &) {
                qCDebug(LIBKLEO_LOG) << "Reloading keycache with remarks enabled";
                QTimer::singleShot(1000, this, [this](){ reload(); });
            });
        }
    } else {
        d->m_remarks_enabled = value;
    }
}

bool KeyCache::remarksEnabled() const
{
    return d->m_remarks_enabled;
}

void KeyCache::Private::refreshJobDone(const KeyListResult &result)
{
    q->enableFileSystemWatcher(true);
    m_initalized = true;
    updateGroupCache();
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

const Subkey &KeyCache::findSubkeyByKeyGrip(const char *grip, Protocol protocol) const
{
    static const Subkey null;
    d->ensureCachePopulated();
    const auto range = std::equal_range(d->by.keygrip.begin(), d->by.keygrip.end(),
                                        grip, _detail::ByKeyGrip<std::less>());
    if (range.first == d->by.keygrip.end()) {
        return null;
    } else if (protocol == UnknownProtocol) {
        return *range.first;
    } else {
        for (auto it = range.first; it != range.second; ++it) {
            if (it->parent().protocol() == protocol) {
                return *it;
            }
        }
    }
    return null;
}

const Subkey &KeyCache::findSubkeyByKeyGrip(const std::string &grip, Protocol protocol) const
{
    return findSubkeyByKeyGrip(grip.c_str(), protocol);
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
    const auto recipients = res.recipients();
    for (const DecryptionResult::Recipient &r : recipients)
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
    const auto signatures = res.signatures();
    for (const Signature &s : signatures)
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
    // Prefer the gnupg normalized one
    const std::string addr = uid.addrSpec();
    if (!addr.empty()) {
        return addr;
    }
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
    const auto userIDs = key.userIDs();
    for (const UserID &uid : userIDs) {
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
            const auto it = std::remove_if(range.first, range.second,
                                           [fpr] (const Subkey &subkey) {
                                               return !qstricmp(fpr, subkey.parent().primaryFingerprint());
                                           });
            d->by.subkeyid.erase(it, range.second);
        }
        if (const char *keygrip = subkey.keyGrip()) {
            const auto range = std::equal_range(d->by.keygrip.begin(), d->by.keygrip.end(), keygrip,
                                                _detail::ByKeyGrip<std::less>());
            const auto it = std::remove_if(range.first, range.second,
                                           [fpr] (const Subkey &subkey) {
                                               return !qstricmp(fpr, subkey.parent().primaryFingerprint());
                                           });
            d->by.keygrip.erase(it, range.second);
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

std::vector<KeyGroup> KeyCache::groups() const
{
    d->ensureCachePopulated();
    return d->m_groups;
}

std::vector<KeyGroup> KeyCache::configurableGroups() const
{
    std::vector<KeyGroup> groups;
    groups.reserve(d->m_groups.size());
    std::copy_if(d->m_groups.cbegin(), d->m_groups.cend(),
                 std::back_inserter(groups),
                 [] (const KeyGroup &group) { return group.source() == KeyGroup::ApplicationConfig; });
    return groups;
}

namespace
{
bool compareById(const KeyGroup &lhs, const KeyGroup &rhs)
{
    return lhs.id() < rhs.id();
}

std::vector<KeyGroup> sortedById(std::vector<KeyGroup> groups)
{
    std::sort(groups.begin(), groups.end(), &compareById);
    return groups;
}
}

void KeyCache::saveConfigurableGroups(const std::vector<KeyGroup> &groups)
{
    const std::vector<KeyGroup> oldGroups = sortedById(configurableGroups());
    const std::vector<KeyGroup> newGroups = sortedById(groups);

    {
        std::vector<KeyGroup> removedGroups;
        std::set_difference(oldGroups.begin(), oldGroups.end(),
                            newGroups.begin(), newGroups.end(),
                            std::back_inserter(removedGroups),
                            &compareById);
        for (const auto &group : std::as_const(removedGroups)) {
            qCDebug(LIBKLEO_LOG) << "Removing group" << group;
            d->remove(group);
        }
    }
    {
        std::vector<KeyGroup> updatedGroups;
        std::set_intersection(newGroups.begin(), newGroups.end(),
                              oldGroups.begin(), oldGroups.end(),
                              std::back_inserter(updatedGroups),
                              &compareById);
        for (const auto &group : std::as_const(updatedGroups)) {
            qCDebug(LIBKLEO_LOG) << "Updating group" << group;
            d->update(group);
        }
    }
    {
        std::vector<KeyGroup> addedGroups;
        std::set_difference(newGroups.begin(), newGroups.end(),
                            oldGroups.begin(), oldGroups.end(),
                            std::back_inserter(addedGroups),
                            &compareById);
        for (const auto &group : std::as_const(addedGroups)) {
            qCDebug(LIBKLEO_LOG) << "Adding group" << group;
            d->insert(group);
        }
    }

    Q_EMIT keysMayHaveChanged();
}

bool KeyCache::insert(const KeyGroup &group)
{
    if (!d->insert(group)) {
        return false;
    }

    Q_EMIT keysMayHaveChanged();

    return true;
}

bool KeyCache::update(const KeyGroup &group)
{
    if (!d->update(group)) {
        return false;
    }

    Q_EMIT keysMayHaveChanged();

    return true;
}

bool KeyCache::remove(const KeyGroup &group)
{
    if (!d->remove(group)) {
        return false;
    }

    Q_EMIT keysMayHaveChanged();

    return true;
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
    using result_type = bool;

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
    by_subkeyid.reserve(subkeys.size() + d->by.subkeyid.size());
    std::merge(subkeys.begin(), subkeys.end(),
               d->by.subkeyid.begin(), d->by.subkeyid.end(),
               std::back_inserter(by_subkeyid),
               _detail::ByKeyID<std::less>());

    // 6c. sort by key grip
    std::sort(subkeys.begin(), subkeys.end(), _detail::ByKeyGrip<std::less>());

    // 6d. insert into subkey keygrip index:
    std::vector<Subkey> by_keygrip;
    by_keygrip.reserve(subkeys.size() + d->by.keygrip.size());
    std::merge(subkeys.begin(), subkeys.end(),
               d->by.keygrip.begin(), d->by.keygrip.end(),
               std::back_inserter(by_keygrip),
               _detail::ByKeyGrip<std::less>());

    // now commit (well, we already removed keys...)
    by_fpr.swap(d->by.fpr);
    by_keyid.swap(d->by.keyid);
    by_shortkeyid.swap(d->by.shortkeyid);
    by_email.swap(d->by.email);
    by_subkeyid.swap(d->by.subkeyid);
    by_keygrip.swap(d->by.keygrip);
    by_chainid.swap(d->by.chainid);

    for (const Key &key : std::as_const(sorted)) {
        d->m_pgpOnly &= key.protocol() == GpgME::OpenPGP;
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

KeyCache::RefreshKeysJob::~RefreshKeysJob()
{
    delete d;
}

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

    For unknown reasons the new style connect fails at runtime
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

    // Only do this for initialized keycaches to avoid huge waits for
    // signature notations during initial keylisting.
    if (proto == GpgME::OpenPGP && m_cache->remarksEnabled() && m_cache->initialized()) {
        auto ctx = QGpgME::Job::context(job);
        if (ctx) {
            ctx->addKeyListMode(KeyListMode::Signatures |
                                KeyListMode::SignatureNotations);
        }
    }

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

bool KeyCache::pgpOnly() const
{
    return d->m_pgpOnly;
}

static bool keyIsOk(const Key &k)
{
    return !k.isExpired() && !k.isRevoked() && !k.isInvalid() && !k.isDisabled();
}

static bool uidIsOk(const UserID &uid)
{
    return keyIsOk(uid.parent()) && !uid.isRevoked() && !uid.isInvalid();
}

static bool subkeyIsOk(const Subkey &s)
{
    return !s.isRevoked() && !s.isInvalid() && !s.isDisabled();
}

namespace
{
time_t creationTimeOfNewestSuitableSubKey(const Key &key, KeyUsage usage)
{
    time_t creationTime = 0;
    for (const Subkey &s: key.subkeys()) {
        if (!subkeyIsOk(s)) {
            continue;
        }
        if (usage == KeyUsage::Sign && !s.canSign()) {
            continue;
        }
        if (usage == KeyUsage::Encrypt && !s.canEncrypt()) {
            continue;
        }
        if (s.creationTime() > creationTime) {
            creationTime = s.creationTime();
        }
    }
    return creationTime;
}

struct BestMatch
{
    Key key;
    UserID uid;
    time_t creationTime = 0;
};
}

GpgME::Key KeyCache::findBestByMailBox(const char *addr, GpgME::Protocol proto, KeyUsage usage) const
{
    d->ensureCachePopulated();
    if (!addr) {
        return {};
    }

    // support lookup of email addresses enclosed in angle brackets
    QByteArray address(addr);
    if (address[0] == '<' && address[address.size() - 1] == '>') {
        address = address.mid(1, address.size() - 2);
    }
    address = address.toLower();

    BestMatch best;
    for (const Key &k: findByEMailAddress(address.constData())) {
        if (proto != Protocol::UnknownProtocol && k.protocol() != proto) {
            continue;
        }
        if (usage == KeyUsage::Encrypt && !k.canEncrypt()) {
            continue;
        }
        if (usage == KeyUsage::Sign && (!k.canSign() || !k.hasSecret())) {
            continue;
        }
        const time_t creationTime = creationTimeOfNewestSuitableSubKey(k, usage);
        if (creationTime == 0) {
            // key does not have a suitable (and usable) subkey
            continue;
        }
        for (const UserID &u: k.userIDs()) {
            if (QByteArray::fromStdString(u.addrSpec()).toLower() != address) {
                // user ID does not match the given email address
                continue;
            }
            if (best.uid.isNull()) {
                // we have found our first candidate
                best = {k, u, creationTime};
            } else if (!uidIsOk(best.uid) && uidIsOk(u)) {
                // validity of the new key is better
                best = {k, u, creationTime};
            } else if (!k.isExpired() && best.uid.validity() < u.validity()) {
                // validity of the new key is better
                best = {k, u, creationTime};
            } else if (best.key.isExpired() && !k.isExpired()) {
                // validity of the new key is better
                best = {k, u, creationTime};
            } else if (best.uid.validity() == u.validity() && uidIsOk(u) && best.creationTime < creationTime) {
                // both keys/user IDs have same validity, but the new key is newer
                best = {k, u, creationTime};
            }
        }
    }

    return best.key;
}

namespace
{
template<typename T>
bool allKeysAllowUsage(const T &keys, KeyUsage usage)
{
    switch(usage) {
    case KeyUsage::AnyUsage:
        return true;
    case KeyUsage::Sign:
        return std::all_of(std::begin(keys), std::end(keys), std::mem_fn(&Key::canSign));
    case KeyUsage::Encrypt:
        return std::all_of(std::begin(keys), std::end(keys), std::mem_fn(&Key::canEncrypt));
    case KeyUsage::Certify:
        return std::all_of(std::begin(keys), std::end(keys), std::mem_fn(&Key::canCertify));
    case KeyUsage::Authenticate:
        return std::all_of(std::begin(keys), std::end(keys), std::mem_fn(&Key::canAuthenticate));
    }
    qCDebug(LIBKLEO_LOG) << __func__ << "called with invalid usage" << int(usage);
    return false;
}

template<typename T>
bool allKeysHaveProtocol(const T &keys, Protocol protocol)
{
    return std::all_of(std::begin(keys), std::end(keys), [protocol] (const auto &key) { return key.protocol() == protocol; });
}
}

KeyGroup KeyCache::findGroup(const QString &name, Protocol protocol, KeyUsage usage) const
{
    d->ensureCachePopulated();

    Q_ASSERT(usage == KeyUsage::Sign || usage == KeyUsage::Encrypt);
    for (const auto &group : std::as_const(d->m_groups)) {
        if (group.name() == name) {
            const KeyGroup::Keys &keys = group.keys();
            if (allKeysAllowUsage(keys, usage)
                && (protocol == UnknownProtocol || allKeysHaveProtocol(keys, protocol))) {
                return group;
            }
        }
    }

    return {};
}

std::vector<Key> KeyCache::getGroupKeys(const QString &groupName) const
{
    std::vector<Key> result;
    for (const KeyGroup &g : std::as_const(d->m_groups)) {
        if (g.name() == groupName) {
            const KeyGroup::Keys &keys = g.keys();
            std::copy(keys.cbegin(), keys.cend(), std::back_inserter(result));
        }
    }
    _detail::sort_by_fpr(result);
    _detail::remove_duplicates_by_fpr(result);
    return result;
}

void KeyCache::setKeys(const std::vector<GpgME::Key>& keys)
{
    // disable regular key listing and cancel running key listing
    setRefreshInterval(0);
    cancelKeyListing();
    clear();
    insert(keys);
    d->m_initalized = true;
    Q_EMIT keyListingDone(KeyListResult());
}

void KeyCache::setGroups(const std::vector<KeyGroup>& groups)
{
    Q_ASSERT(d->m_initalized && "Call setKeys() before setting groups");
    d->m_groups = groups;
    Q_EMIT keysMayHaveChanged();
}

#include "moc_keycache_p.cpp"
#include "moc_keycache.cpp"
