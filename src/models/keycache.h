/* -*- mode: c++; c-basic-offset:4 -*-
    models/keycache.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <kleo_export.h>

#include <gpgme++/global.h>

#include <memory>
#include <string>
#include <vector>

namespace GpgME
{
class Key;
class DecryptionResult;
class VerificationResult;
class KeyListResult;
class Subkey;
}

namespace KMime
{
namespace Types
{
class Mailbox;
}
}

namespace Kleo
{

class FileSystemWatcher;
class KeyGroup;
enum class KeyUsage : char;

class KLEO_EXPORT KeyCache : public QObject
{
    Q_OBJECT
protected:
    explicit KeyCache();
public:
    static std::shared_ptr<const KeyCache> instance();
    static std::shared_ptr<KeyCache> mutableInstance();

    ~KeyCache();

    void setGroupsEnabled(bool enabled);
    void setGroupsConfig(const QString &filename);

    void insert(const GpgME::Key &key);
    void insert(const std::vector<GpgME::Key> &keys);
    bool insert(const KeyGroup &group);

    void refresh(const std::vector<GpgME::Key> &keys);
    bool update(const KeyGroup &group);

    void remove(const GpgME::Key &key);
    void remove(const std::vector<GpgME::Key> &keys);
    bool remove(const KeyGroup &group);

    void addFileSystemWatcher(const std::shared_ptr<FileSystemWatcher> &watcher);

    void enableFileSystemWatcher(bool enable);

    void setRefreshInterval(int hours);
    int refreshInterval() const;

    void enableRemarks(bool enable);
    bool remarksEnabled() const;

    const std::vector<GpgME::Key> &keys() const;
    std::vector<GpgME::Key> secretKeys() const;

    std::vector<KeyGroup> groups() const;
    std::vector<KeyGroup> configurableGroups() const;
    void saveConfigurableGroups(const std::vector<KeyGroup> &groups);

    const GpgME::Key &findByFingerprint(const char *fpr) const;
    const GpgME::Key &findByFingerprint(const std::string &fpr) const;

    std::vector<GpgME::Key> findByEMailAddress(const char *email) const;
    std::vector<GpgME::Key> findByEMailAddress(const std::string &email) const;

    /** Look through the cache and search for the best key for a mailbox.
     *
     * The best key is the key with a UID for the provided mailbox that
     * has the highest validity and a subkey that is capable for the given
     * usage.
     * If more then one key have a UID with the same validity
     * the most recently created key is taken.
     *
     * @returns the "best" key for the mailbox. */
    GpgME::Key findBestByMailBox(const char *addr, GpgME::Protocol proto, KeyUsage usage) const;

    /**
     * Looks for a group named @a name which contains keys with protocol @a protocol
     * that are suitable for the usage @a usage.
     *
     * If @a protocol is GpgME::OpenPGP or GpgME::CMS, then only groups consisting of keys
     * matching this protocol are considered. Use @a protocol GpgME::UnknownProtocol to consider
     * any groups regardless of the protocol including mixed-protocol groups.
     *
     * If @a usage is not KeyUsage::AnyUsage, then only groups consisting of keys supporting this usage
     * are considered.
     * The validity of keys and the presence of a private key (necessary for signing, certification, and
     * authentication) is not taken into account.
     *
     * The first group that fulfills all conditions is returned.
     *
     * @returns a matching group or a null group if no matching group is found.
     */
    KeyGroup findGroup(const QString &name, GpgME::Protocol protocol, KeyUsage usage) const;

    const GpgME::Key &findByShortKeyID(const char *id) const;
    const GpgME::Key &findByShortKeyID(const std::string &id) const;

    const GpgME::Key &findByKeyIDOrFingerprint(const char *id) const;
    const GpgME::Key &findByKeyIDOrFingerprint(const std::string &id) const;

    std::vector<GpgME::Key> findByKeyIDOrFingerprint(const std::vector<std::string> &ids) const;

    const GpgME::Subkey &findSubkeyByKeyGrip(const char *grip, GpgME::Protocol protocol = GpgME::UnknownProtocol) const;
    const GpgME::Subkey &findSubkeyByKeyGrip(const std::string &grip, GpgME::Protocol protocol = GpgME::UnknownProtocol) const;

    std::vector<GpgME::Subkey> findSubkeysByKeyID(const std::vector<std::string> &ids) const;

    std::vector<GpgME::Key> findRecipients(const GpgME::DecryptionResult &result) const;
    std::vector<GpgME::Key> findSigners(const GpgME::VerificationResult &result) const;

    std::vector<GpgME::Key> findSigningKeysByMailbox(const QString &mb) const;
    std::vector<GpgME::Key> findEncryptionKeysByMailbox(const QString &mb) const;

    /** Check for group keys.
     *
     * @returns A list of keys configured for groupName. Empty if no group cached.*/
    std::vector<GpgME::Key> getGroupKeys(const QString &groupName) const;

    enum Option {
        NoOption = 0,
        RecursiveSearch = 1,
        IncludeSubject = 2
    };
    Q_DECLARE_FLAGS(Options, Option)

    std::vector<GpgME::Key> findSubjects(const GpgME::Key &key, Options option = RecursiveSearch) const;
    std::vector<GpgME::Key> findSubjects(const std::vector<GpgME::Key> &keys, Options options = RecursiveSearch) const;
    std::vector<GpgME::Key> findSubjects(std::vector<GpgME::Key>::const_iterator first, std::vector<GpgME::Key>::const_iterator last, Options options = RecursiveSearch) const;

    std::vector<GpgME::Key> findIssuers(const GpgME::Key &key, Options options = RecursiveSearch) const;
    std::vector<GpgME::Key> findIssuers(const std::vector<GpgME::Key> &keys, Options options = RecursiveSearch) const;
    std::vector<GpgME::Key> findIssuers(std::vector<GpgME::Key>::const_iterator first, std::vector<GpgME::Key>::const_iterator last, Options options = RecursiveSearch) const;

    /** Check if at least one keylisting was finished. */
    bool initialized() const;

    /** Check if all keys have OpenPGP Protocol. */
    bool pgpOnly() const;

    /** Set the keys the cache shall contain. Marks cache as initialized. Use for tests only. */
    void setKeys(const std::vector<GpgME::Key> &keys);

    void setGroups(const std::vector<KeyGroup> &groups);

public Q_SLOTS:
    void clear();
    void startKeyListing(GpgME::Protocol proto = GpgME::UnknownProtocol)
    {
        reload(proto);
    }
    void reload(GpgME::Protocol proto = GpgME::UnknownProtocol);
    void cancelKeyListing();

Q_SIGNALS:
    //void changed( const GpgME::Key & key );
    void aboutToRemove(const GpgME::Key &key);
    void added(const GpgME::Key &key);
    void keyListingDone(const GpgME::KeyListResult &result);
    void keysMayHaveChanged();
    void groupAdded(const Kleo::KeyGroup &group);
    void groupUpdated(const Kleo::KeyGroup &group);
    void groupRemoved(const Kleo::KeyGroup &group);

private:
    class RefreshKeysJob;

    class Private;
    QScopedPointer<Private> const d;
};

}

Q_DECLARE_OPERATORS_FOR_FLAGS(Kleo::KeyCache::Options)

