/*
    utils/uniquelock.cpp
    QMutex-compatible replacement for std::UniqueLock

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008-2021 Free Software Foundation, Inc.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-3.0-or-later+GCC Runtime Library Exception
*/

#include <config-libkleo.h>

#include "uniquelock.h"

#include <libkleo_debug.h>

#include <QDebug>

namespace Kleo
{

UniqueLock::UniqueLock() noexcept
    : mMutex{nullptr}, mOwnsMutex{false}
{
}

UniqueLock::UniqueLock(QMutex &mutex)
    : mMutex{std::addressof(mutex)}, mOwnsMutex{false}
{
    lock();
    mOwnsMutex = true;
}

UniqueLock::UniqueLock(QMutex &mutex, DeferLockType) noexcept
    : mMutex{std::addressof(mutex)}, mOwnsMutex{false}
{
}

UniqueLock::UniqueLock(QMutex &mutex, TryToLockType)
    : mMutex{std::addressof(mutex)}, mOwnsMutex{mMutex->try_lock()}
{
}

UniqueLock::UniqueLock(QMutex &mutex, AdoptLockType) noexcept
    : mMutex{std::addressof(mutex)}, mOwnsMutex{true}
{
    // XXX calling thread owns mutex
}

UniqueLock::~UniqueLock()
{
    if (mOwnsMutex) {
        unlock();
    }
}

UniqueLock::UniqueLock(UniqueLock &&u) noexcept
    : mMutex{u.mMutex}, mOwnsMutex{u.mOwnsMutex}
{
    u.mMutex = nullptr;
    u.mOwnsMutex = false;
}

UniqueLock &UniqueLock::operator=(UniqueLock &&u) noexcept
{
    if(mOwnsMutex) {
        unlock();
    }

    UniqueLock(std::move(u)).swap(*this);

    u.mMutex = nullptr;
    u.mOwnsMutex = false;

    return *this;
}

void UniqueLock::lock()
{
    Q_ASSERT(mMutex);
    Q_ASSERT(!mOwnsMutex);
    if (!mMutex) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Error: operation not permitted";
    } else if (mOwnsMutex) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Error: resource deadlock would occur";
    } else {
        mMutex->lock();
        mOwnsMutex = true;
    }
}

bool UniqueLock::try_lock()
{
    Q_ASSERT(mMutex);
    Q_ASSERT(!mOwnsMutex);
    if (!mMutex) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Error: operation not permitted";
        return false;
    } else if (mOwnsMutex) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Error: resource deadlock would occur";
        return false;
    } else {
        mOwnsMutex = mMutex->try_lock();
        return mOwnsMutex;
    }
}

void UniqueLock::unlock()
{
    if (!mOwnsMutex) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Error: operation not permitted";
    } else if (mMutex) {
        mMutex->unlock();
        mOwnsMutex = false;
    }
}

void UniqueLock::swap(UniqueLock &u) noexcept
{
    std::swap(mMutex, u.mMutex);
    std::swap(mOwnsMutex, u.mOwnsMutex);
}

QMutex *UniqueLock::release() noexcept
{
    QMutex *ret = mMutex;
    mMutex = nullptr;
    mOwnsMutex = false;
    return ret;
}

bool UniqueLock::owns_lock() const noexcept
{
    return mOwnsMutex;
}

UniqueLock::operator bool() const noexcept
{
    return owns_lock();
}

QMutex *UniqueLock::mutex() const noexcept
{
    return mMutex;
}

} // namespace Kleo
