/*  -*- c++ -*-
    keyselectiondialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    Based on kpgpui.h
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEO_UI_KEYSELECTIONDIALOG_H__
#define __KLEO_UI_KEYSELECTIONDIALOG_H__

#include "kleo_export.h"

#include <gpgme++/key.h>
#include <qgpgme/protocol.h>

#include <QDialog>

#include <QPixmap>

#include <vector>

class QVBoxLayout;
class QCheckBox;
class QPixmap;
class QTimer;
class QRegExp;
class QPoint;

namespace Kleo
{
class KeyListView;
class KeyListViewItem;
}

namespace GpgME
{
class KeyListResult;
}

namespace Kleo
{

class KLEO_EXPORT KeySelectionDialog : public QDialog
{
    Q_OBJECT
public:

    enum KeyUsage {
        PublicKeys = 1,
        SecretKeys = 2,
        EncryptionKeys = 4,
        SigningKeys = 8,
        ValidKeys = 16,
        TrustedKeys = 32,
        CertificationKeys = 64,
        AuthenticationKeys = 128,
        OpenPGPKeys = 256,
        SMIMEKeys = 512,
        AllKeys = PublicKeys | SecretKeys | OpenPGPKeys | SMIMEKeys,
        ValidEncryptionKeys = AllKeys | EncryptionKeys | ValidKeys,
        ValidTrustedEncryptionKeys = AllKeys | EncryptionKeys | ValidKeys | TrustedKeys
    };

    KeySelectionDialog(const QString &title,
                       const QString &text,
                       const std::vector<GpgME::Key> &selectedKeys = std::vector<GpgME::Key>(),
                       unsigned int keyUsage = AllKeys,
                       bool extendedSelection = false,
                       bool rememberChoice = false,
                       QWidget *parent = nullptr,
                       bool modal = true);
    KeySelectionDialog(const QString &title,
                       const QString &text,
                       const QString &initialPattern,
                       const std::vector<GpgME::Key> &selectedKeys,
                       unsigned int keyUsage = AllKeys,
                       bool extendedSelection = false,
                       bool rememberChoice = false,
                       QWidget *parent = nullptr,
                       bool modal = true);
    KeySelectionDialog(const QString &title,
                       const QString &text,
                       const QString &initialPattern,
                       unsigned int keyUsage = AllKeys,
                       bool extendedSelection = false,
                       bool rememberChoice = false,
                       QWidget *parent = nullptr,
                       bool modal = true);
    ~KeySelectionDialog();

    /** Returns the key ID of the selected key in single selection mode.
        Otherwise it returns a null key. */
    const GpgME::Key &selectedKey() const;

    QString fingerprint() const;

    /** Returns a list of selected key IDs. */
    const std::vector<GpgME::Key> &selectedKeys() const
    {
        return mSelectedKeys;
    }

    /// Return all the selected fingerprints
    QStringList fingerprints() const;

    /// Return the selected openpgp fingerprints
    QStringList pgpKeyFingerprints() const;
    /// Return the selected smime fingerprints
    QStringList smimeFingerprints() const;

    bool rememberSelection() const;

    // Could be used by derived classes to insert their own widget
    QVBoxLayout *topLayout() const
    {
        return mTopLayout;
    }

private Q_SLOTS:
    void slotRereadKeys();
    void slotStartCertificateManager(const QString &query = QString());
    void slotStartSearchForExternalCertificates()
    {
        slotStartCertificateManager(mInitialQuery);
    }
    void slotKeyListResult(const GpgME::KeyListResult &);
    void slotSelectionChanged();
    void slotCheckSelection()
    {
        slotCheckSelection(nullptr);
    }
    void slotCheckSelection(Kleo::KeyListViewItem *);
    void slotRMB(Kleo::KeyListViewItem *, const QPoint &);
    void slotRecheckKey();
    void slotTryOk();
    void slotOk();
    void slotCancel();
    void slotSearch(const QString &text);
    void slotSearch();
    void slotFilter();

private:
    void filterByKeyID(const QString &keyID);
    void filterByKeyIDOrUID(const QString &keyID);
    void filterByUID(const QString &uid);
    void showAllItems();
    bool anyChildMatches(const Kleo::KeyListViewItem *item, QRegExp &rx) const;

    void connectSignals();
    void disconnectSignals();

    void startKeyListJobForBackend(const QGpgME::Protocol *, const std::vector<GpgME::Key> &, bool);
    void startValidatingKeyListing();

    void init(bool, bool, const QString &, const QString &);

private:
    QVBoxLayout *mTopLayout = nullptr;
    Kleo::KeyListView *mKeyListView = nullptr;
    const QGpgME::Protocol *mOpenPGPBackend = nullptr;
    const QGpgME::Protocol *mSMIMEBackend = nullptr;
    QCheckBox *mRememberCB = nullptr;
    std::vector<GpgME::Key> mSelectedKeys, mKeysToCheck;
    unsigned int mKeyUsage;
    QTimer *mCheckSelectionTimer = nullptr;
    QTimer *mStartSearchTimer = nullptr;
    // cross-eventloop temporaries:
    QString mSearchText;
    const QString mInitialQuery;
    Kleo::KeyListViewItem *mCurrentContextMenuItem = nullptr;
    int mTruncated, mListJobCount, mSavedOffsetY;
    QPushButton *mOkButton = nullptr;
};

}

#endif // __KLEO_UI_KEYSELECTIONDIALOG_H__
