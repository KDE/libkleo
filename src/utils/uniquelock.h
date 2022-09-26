/*
    utils/uniquelock.h
    QMutex-compatible replacement for std::unique_lock

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008-2021 Free Software Foundation, Inc.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
*/

#pragma once

#include "kleo_export.h"

#include <QMutex>

#include <chrono>
#include <memory>

namespace Kleo
{

/// Do not acquire ownership of the mutex.
struct DeferLockType {
    explicit DeferLockType() = default;
};

/// Try to acquire ownership of the mutex without blocking.
struct TryToLockType {
    explicit TryToLockType() = default;
};

/// Assume the calling thread has already obtained mutex ownership
/// and manage it.
struct AdoptLockType {
    explicit AdoptLockType() = default;
};

/// Tag used to prevent a scoped lock from acquiring ownership of a mutex.
inline constexpr DeferLockType deferLock{};

/// Tag used to prevent a scoped lock from blocking if a mutex is locked.
inline constexpr TryToLockType tryToLock{};

/// Tag used to make a scoped lock take ownership of a locked mutex.
inline constexpr AdoptLockType adoptLock{};

/** @brief A movable scoped lock type for QMutex.
 *
 * A UniqueLock controls mutex ownership within a scope. Ownership of the
 * mutex can be delayed until after construction and can be transferred
 * to another UniqueLock by move construction or move assignment. If a
 * mutex lock is owned when the destructor runs ownership will be released.
 */
class KLEO_EXPORT UniqueLock
{
public:
    UniqueLock() noexcept;
    explicit UniqueLock(QMutex &mutex);

    UniqueLock(QMutex &mutex, DeferLockType) noexcept;
    UniqueLock(QMutex &mutex, TryToLockType);
    UniqueLock(QMutex &mutex, AdoptLockType) noexcept;

    template<typename Clock, typename Duration>
    UniqueLock(QMutex &mutex, const std::chrono::time_point<Clock, Duration> &timePoint)
        : mMutex{std::addressof(mutex)}
        , mOwnsMutex{mMutex->try_lock_until(timePoint)}
    {
    }

    template<typename Rep, typename Period>
    UniqueLock(QMutex &mutex, const std::chrono::duration<Rep, Period> &duration)
        : mMutex{std::addressof(mutex)}
        , mOwnsMutex{mMutex->try_lock_for(duration)}
    {
    }

    ~UniqueLock();

    UniqueLock(const UniqueLock &) = delete;
    UniqueLock &operator=(const UniqueLock &) = delete;

    UniqueLock(UniqueLock &&u) noexcept;
    UniqueLock &operator=(UniqueLock &&u) noexcept;

    void lock();

    bool try_lock();

    template<typename Clock, typename Duration>
    bool try_lock_until(const std::chrono::time_point<Clock, Duration> &timePoint)
    {
        Q_ASSERT(mMutex);
        Q_ASSERT(!mOwnsMutex);
        if (mMutex && !mOwnsMutex) {
            mOwnsMutex = mMutex->try_lock_until(timePoint);
            return mOwnsMutex;
        }
    }

    template<typename Rep, typename Period>
    bool try_lock_for(const std::chrono::duration<Rep, Period> &duration)
    {
        Q_ASSERT(mMutex);
        Q_ASSERT(!mOwnsMutex);
        if (mMutex && !mOwnsMutex) {
            mOwnsMutex = mMutex->try_lock_for(duration);
            return mOwnsMutex;
        }
    }

    void unlock();

    void swap(UniqueLock &u) noexcept;

    QMutex *release() noexcept;

    bool owns_lock() const noexcept;

    explicit operator bool() const noexcept;

    QMutex *mutex() const noexcept;

private:
    QMutex *mMutex;
    bool mOwnsMutex;
};

} // namespace Kleo

namespace std
{

/// Swap overload for UniqueLock objects.
/// @relates UniqueLock
inline void swap(Kleo::UniqueLock &x, Kleo::UniqueLock &y) noexcept
{
    x.swap(y);
}

}
