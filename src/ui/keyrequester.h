/*  -*- c++ -*-
    keyrequester.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    Based on kpgpui.h
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    This file is part of KPGP, the KDE PGP/GnuPG support library.

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "kleo_export.h"

#include <qgpgme/protocol.h>

#include <QWidget>
#include <QLabel>

#include <vector>

namespace GpgME
{
class Key;
class KeyListResult;
}

#include <QStringList>
class QString;
class QPushButton;

namespace Kleo
{

/// Base class for SigningKeyRequester and EncryptionKeyRequester
class KLEO_EXPORT KeyRequester : public QWidget
{
    Q_OBJECT
public:
    explicit KeyRequester(unsigned int allowedKeys, bool multipleKeys = false,
                          QWidget *parent = nullptr);
    // Constructor for Qt Designer
    explicit KeyRequester(QWidget *parent = nullptr);
    ~KeyRequester();

    const GpgME::Key &key() const;
    /** Preferred method to set a key for
        non-multi-KeyRequesters. Doesn't start a backend
        KeyListJob.
    */
    void setKey(const GpgME::Key &key);

    const std::vector<GpgME::Key> &keys() const;
    /** Preferred method to set a key for multi-KeyRequesters. Doesn't
        start a backend KeyListJob.
    */
    void setKeys(const std::vector<GpgME::Key> &keys);

    QString fingerprint() const;
    /** Set the key by fingerprint. Starts a background KeyListJob to
        retrieve the complete GpgME::Key object
    */
    void setFingerprint(const QString &fingerprint);

    QStringList fingerprints() const;
    /** Set the keys by fingerprint. Starts a background KeyListJob to
        retrieve the complete GpgME::Key objects
    */
    void setFingerprints(const QStringList &fingerprints);

    QPushButton *eraseButton();
    QPushButton *dialogButton();

    void setDialogCaption(const QString &caption);
    void setDialogMessage(const QString &message);

    bool isMultipleKeysEnabled() const;
    void setMultipleKeysEnabled(bool enable);

    unsigned int allowedKeys() const;
    void setAllowedKeys(unsigned int allowed);

    void setInitialQuery(const QString &s)
    {
        mInitialQuery = s;
    }
    const QString &initialQuery() const
    {
        return mInitialQuery;
    }

Q_SIGNALS:
    void changed();

private:
    void init();
    void startKeyListJob(const QStringList &fingerprints);
    void updateKeys();

private Q_SLOTS:
    void slotNextKey(const GpgME::Key &key);
    void slotKeyListResult(const GpgME::KeyListResult &result);
    void slotDialogButtonClicked();
    void slotEraseButtonClicked();

private:
    const QGpgME::Protocol *mOpenPGPBackend = nullptr;
    const QGpgME::Protocol *mSMIMEBackend = nullptr;
    QLabel *mLabel = nullptr;
    QPushButton *mEraseButton = nullptr;
    QPushButton *mDialogButton = nullptr;
    QString mDialogCaption, mDialogMessage, mInitialQuery;
    bool mMulti;
    unsigned int mKeyUsage;
    int mJobs;
    std::vector<GpgME::Key> mKeys;
    std::vector<GpgME::Key> mTmpKeys;

private:
    class Private;
    Private *const d;
protected:
    virtual void virtual_hook(int, void *);
};

class KLEO_EXPORT EncryptionKeyRequester : public KeyRequester
{
    Q_OBJECT
public:
    enum { OpenPGP = 1, SMIME = 2, AllProtocols = OpenPGP | SMIME };

    /**
     * Preferred constructor
     */
    explicit EncryptionKeyRequester(bool multipleKeys = false,
                                    unsigned int proto = AllProtocols,
                                    QWidget *parent = nullptr,
                                    bool onlyTrusted = true,
                                    bool onlyValid = true);
    /**
     * Constructor for Qt designer
     */
    explicit EncryptionKeyRequester(QWidget *parent);
    ~EncryptionKeyRequester();

    void setAllowedKeys(unsigned int proto, bool onlyTrusted = true, bool onlyValid = true);

private:
    class Private;
    Private *const d;
protected:
    void virtual_hook(int, void *) override;
};

class KLEO_EXPORT SigningKeyRequester : public KeyRequester
{
    Q_OBJECT
public:
    enum { OpenPGP = 1, SMIME = 2, AllProtocols = OpenPGP | SMIME };

    /**
     * Preferred constructor
     * @param multipleKeys whether multiple keys can be selected
     *
     * @param proto the allowed protocols, OpenPGP and/or SMIME
     * @param parent the parent widget
     * @param onlyTrusted only show trusted keys
     * @param onlyValid only show valid keys
     */
    explicit SigningKeyRequester(bool multipleKeys = false,
                                 unsigned int proto = AllProtocols,
                                 QWidget *parent = nullptr,
                                 bool onlyTrusted = true, bool onlyValid = true);
    /**
     * Constructor for Qt designer
     */
    explicit SigningKeyRequester(QWidget *parent);
    ~SigningKeyRequester();

    /*
     * Those parameters affect the parameters given to the key selection dialog.
     * @param proto the allowed protocols, OpenPGP and/or SMIME
     * @param onlyTrusted only show trusted keys
     * @param onlyValid only show valid keys
     */
    void setAllowedKeys(unsigned int proto, bool onlyTrusted = true, bool onlyValid = true);

private:
    class Private;
    Private *const d;
protected:
    void virtual_hook(int, void *) override;
};

}

