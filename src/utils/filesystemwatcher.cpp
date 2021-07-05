/* -*- mode: c++; c-basic-offset:4 -*-
    filesystemwatcher.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "filesystemwatcher.h"
#include "kleo/stl_util.h"

#include <libkleo_debug.h>

#include <QFileSystemWatcher>
#include <QString>
#include <QTimer>
#include <QDir>

#include <set>

using namespace Kleo;

class FileSystemWatcher::Private
{
    FileSystemWatcher *const q;
public:
    explicit Private(FileSystemWatcher *qq, const QStringList &paths = QStringList());
    ~Private()
    {
        delete m_watcher;
    }

    void onFileChanged(const QString &path);
    void onDirectoryChanged(const QString &path);
    void handleTimer();
    void onTimeout();

    void connectWatcher();

    QFileSystemWatcher *m_watcher = nullptr;
    QTimer m_timer;
    std::set<QString> m_seenPaths;
    std::set<QString> m_cachedDirectories;
    std::set<QString> m_cachedFiles;
    QStringList m_paths, m_blacklist, m_whitelist;
};

FileSystemWatcher::Private::Private(FileSystemWatcher *qq, const QStringList &paths)
    : q(qq),
      m_watcher(nullptr),
      m_paths(paths)
{
    m_timer.setSingleShot(true);
    connect(&m_timer, &QTimer::timeout, q, [this]() { onTimeout(); });
}

static bool is_matching(const QString &file, const QStringList &list)
{
    for (const QString &entry : list)
        if (QRegExp(entry, Qt::CaseInsensitive, QRegExp::Wildcard).exactMatch(file)) {
            return true;
        }
    return false;
}

static bool is_blacklisted(const QString &file, const QStringList &blacklist)
{
    return is_matching(file, blacklist);
}

static bool is_whitelisted(const QString &file, const QStringList &whitelist)
{
    if (whitelist.empty()) {
        return true;    // special case
    }
    return is_matching(file, whitelist);
}

void FileSystemWatcher::Private::onFileChanged(const QString &path)
{
    const QFileInfo fi(path);
    if (is_blacklisted(fi.fileName(), m_blacklist)) {
        return;
    }
    if (!is_whitelisted(fi.fileName(), m_whitelist)) {
        return;
    }
    qCDebug(LIBKLEO_LOG) << path;
    m_seenPaths.insert(path);
    m_cachedFiles.insert(path);
    handleTimer();
}

static QStringList list_dir_absolute(const QString &path, const QStringList &blacklist, const QStringList &whitelist)
{
    QDir dir(path);
    QStringList entries = dir.entryList(QDir::AllEntries | QDir::NoDotAndDotDot);
    QStringList::iterator end =
        std::remove_if(entries.begin(), entries.end(),
                       [&blacklist](const QString &entry) {
                           return is_blacklisted(entry, blacklist);
                       });
    if (!whitelist.empty())
        end = std::remove_if(entries.begin(), end,
                             [&whitelist](const QString &entry) {
                                 return !is_whitelisted(entry, whitelist);
                             });
    entries.erase(end, entries.end());
    std::sort(entries.begin(), entries.end());

    std::transform(entries.begin(), entries.end(), entries.begin(),
                   [&dir](const QString &entry) {
                       return dir.absoluteFilePath(entry);
                   });

    return entries;
}

static QStringList find_new_files(const QStringList &current, const std::set<QString> &seen)
{
    QStringList result;
    std::set_difference(current.begin(), current.end(),
                        seen.begin(), seen.end(),
                        std::back_inserter(result));
    return result;
}

void FileSystemWatcher::Private::onDirectoryChanged(const QString &path)
{
    const QStringList newFiles = find_new_files(list_dir_absolute(path, m_blacklist, m_whitelist), m_seenPaths);

    if (newFiles.empty()) {
        return;
    }

    qCDebug(LIBKLEO_LOG) << "newFiles" << newFiles;

    m_cachedFiles.insert(newFiles.begin(), newFiles.end());
    q->addPaths(newFiles);

    m_cachedDirectories.insert(path);
    handleTimer();
}

void FileSystemWatcher::Private::onTimeout()
{
    std::set<QString> dirs, files;

    dirs.swap(m_cachedDirectories);
    files.swap(m_cachedFiles);

    if (dirs.empty() && files.empty()) {
        return;
    }

    Q_EMIT q->triggered();

    for (const QString &i : std::as_const(dirs)) {
        Q_EMIT q->directoryChanged(i);
    }
    for (const QString &i : std::as_const(files)) {
        Q_EMIT q->fileChanged(i);
    }
}

void FileSystemWatcher::Private::handleTimer()
{
    if (m_timer.interval() == 0) {
        onTimeout();
        return;
    }
    m_timer.start();
}

void FileSystemWatcher::Private::connectWatcher()
{
    if (!m_watcher) {
        return;
    }
    connect(m_watcher, &QFileSystemWatcher::directoryChanged, q, [this](const QString &str) { onDirectoryChanged(str); });
    connect(m_watcher, &QFileSystemWatcher::fileChanged, q, [this](const QString &str) { onFileChanged(str); });
}

FileSystemWatcher::FileSystemWatcher(QObject *p)
    : QObject(p), d(new Private(this))
{
    setEnabled(true);
}

FileSystemWatcher::FileSystemWatcher(const QStringList &paths, QObject *p)
    : QObject(p), d(new Private(this, paths))
{
    setEnabled(true);
}

void FileSystemWatcher::setEnabled(bool enable)
{
    if (isEnabled() == enable) {
        return;
    }
    if (enable) {
        Q_ASSERT(!d->m_watcher);
        d->m_watcher = new QFileSystemWatcher;
        if (!d->m_paths.empty()) {
            d->m_watcher->addPaths(d->m_paths);
        }
        d->connectWatcher();
    } else {
        Q_ASSERT(d->m_watcher);
        delete d->m_watcher;
        d->m_watcher = nullptr;
    }
}

bool FileSystemWatcher::isEnabled() const
{
    return d->m_watcher != nullptr;
}

FileSystemWatcher::~FileSystemWatcher()
{
}

void FileSystemWatcher::setDelay(int ms)
{
    Q_ASSERT(ms >= 0);
    d->m_timer.setInterval(ms);
}

int FileSystemWatcher::delay() const
{
    return d->m_timer.interval();
}

void FileSystemWatcher::blacklistFiles(const QStringList &paths)
{
    d->m_blacklist += paths;
    QStringList blacklisted;
    d->m_paths.erase(kdtools::separate_if(d->m_paths.begin(), d->m_paths.end(),
                                          std::back_inserter(blacklisted), d->m_paths.begin(),
                                          [this](const QString &path) {
                                              return is_blacklisted(path, d->m_blacklist);
                                          }).second, d->m_paths.end());
    if (d->m_watcher && !blacklisted.empty()) {
        d->m_watcher->removePaths(blacklisted);
    }
}

void FileSystemWatcher::whitelistFiles(const QStringList &patterns)
{
    d->m_whitelist += patterns;
    // ### would be nice to add newly-matching paths here right away,
    // ### but it's not as simple as blacklisting above, esp. since we
    // ### don't want to subject addPath()'ed paths to whitelisting.
}

static QStringList resolve(const QStringList &paths, const QStringList &blacklist, const QStringList &whitelist)
{
    if (paths.empty()) {
        return QStringList();
    }
    QStringList result;
    for (const QString &path : paths)
        if (QDir(path).exists()) {
            result += list_dir_absolute(path, blacklist, whitelist);
        }
    return result + resolve(result, blacklist, whitelist);
}

void FileSystemWatcher::addPaths(const QStringList &paths)
{
    if (paths.empty()) {
        return;
    }
    const QStringList newPaths = paths + resolve(paths, d->m_blacklist, d->m_whitelist);
    if (!newPaths.empty()) {
        qCDebug(LIBKLEO_LOG) << "adding\n " << newPaths.join(QLatin1String("\n ")) << "\n/end";
    }
    d->m_paths += newPaths;
    d->m_seenPaths.insert(newPaths.begin(), newPaths.end());
    if (d->m_watcher && !newPaths.empty()) {
        d->m_watcher->addPaths(newPaths);
    }
}

void FileSystemWatcher::addPath(const QString &path)
{
    addPaths(QStringList(path));
}

void FileSystemWatcher::removePaths(const QStringList &paths)
{
    if (paths.empty()) {
        return;
    }
    for (const QString &i : paths) {
        d->m_paths.removeAll(i);
    }
    if (d->m_watcher) {
        d->m_watcher->removePaths(paths);
    }
}

void FileSystemWatcher::removePath(const QString &path)
{
    removePaths(QStringList(path));
}

#include "moc_filesystemwatcher.cpp"
