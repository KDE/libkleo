/*
    cryptoconfigmodule_p.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2004, 2005 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <QList>

class KLineEdit;
class QSpinBox;

class QPushButton;
class QGridLayout;
class QLabel;
class QCheckBox;
class QComboBox;

namespace Kleo
{
class FileNameRequester;
}

namespace QGpgME
{
class CryptoConfig;
class CryptoConfigComponent;
class CryptoConfigGroup;
class CryptoConfigEntry;
} // namespace QGpgME

namespace Kleo
{
class CryptoConfigComponentGUI;
class CryptoConfigGroupGUI;
class CryptoConfigEntryGUI;

/**
 * A widget corresponding to a component in the crypto config
 */
class CryptoConfigComponentGUI : public QWidget
{
    Q_OBJECT

public:
    CryptoConfigComponentGUI(CryptoConfigModule *module, QGpgME::CryptoConfigComponent *component,
                             QWidget *parent = nullptr);

    bool save();
    void load();
    void defaults();

private:
    QGpgME::CryptoConfigComponent *mComponent = nullptr;
    QList<CryptoConfigGroupGUI *> mGroupGUIs;
};

/**
 * A class managing widgets corresponding to a group in the crypto config
 */
class CryptoConfigGroupGUI : public QObject
{
    Q_OBJECT

public:
    CryptoConfigGroupGUI(CryptoConfigModule *module, QGpgME::CryptoConfigGroup *group,
                         QGridLayout *layout, QWidget *parent = nullptr);

    bool save();
    void load();
    void defaults();

private:
    QGpgME::CryptoConfigGroup *mGroup = nullptr;
    QList<CryptoConfigEntryGUI *> mEntryGUIs;
};

/**
 * Factory for CryptoConfigEntryGUI instances
 * Not a real factory, but can become one later.
 */
class CryptoConfigEntryGUIFactory
{
public:
    static CryptoConfigEntryGUI *createEntryGUI(
        CryptoConfigModule *module,
        QGpgME::CryptoConfigEntry *entry, const QString &entryName,
        QGridLayout *layout, QWidget *widget);
};

/**
 * Base class for the widget managers tied to an entry in the crypto config
 */
class CryptoConfigEntryGUI : public QObject
{
    Q_OBJECT
public:
    CryptoConfigEntryGUI(CryptoConfigModule *module,
                         QGpgME::CryptoConfigEntry *entry,
                         const QString &entryName);

    void load()
    {
        doLoad();
        mChanged = false;
    }
    void save()
    {
        Q_ASSERT(mChanged);
        doSave();
        mChanged = false;
    }
    void resetToDefault();

    QString description() const;
    bool isChanged() const
    {
        return mChanged;
    }

Q_SIGNALS:
    void changed();

protected Q_SLOTS:
    void slotChanged()
    {
        mChanged = true;
        Q_EMIT changed();
    }

protected:
    virtual void doSave() = 0;
    virtual void doLoad() = 0;

    QGpgME::CryptoConfigEntry *mEntry = nullptr;
    QString mName;
    bool mChanged = false;
};

/**
 * A widget manager for a string entry in the crypto config
 */
class CryptoConfigEntryLineEdit : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntryLineEdit(CryptoConfigModule *module,
                              QGpgME::CryptoConfigEntry *entry,
                              const QString &entryName,
                              QGridLayout *layout,
                              QWidget *parent = nullptr);

    void doSave() override;
    void doLoad() override;
private:
    KLineEdit *mLineEdit = nullptr;
};

/**
 * A widget manager for a debug-level entry in the crypto config
 */
class CryptoConfigEntryDebugLevel : public CryptoConfigEntryGUI
{
    Q_OBJECT
public:
    CryptoConfigEntryDebugLevel(CryptoConfigModule *module, QGpgME::CryptoConfigEntry *entry,
                                const QString &entryName, QGridLayout *layout, QWidget *parent = nullptr);

    void doSave() override;
    void doLoad() override;
private:
    QComboBox *mComboBox = nullptr;
};

/**
 * A widget manager for a path entry in the crypto config
 */
class CryptoConfigEntryPath : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntryPath(CryptoConfigModule *module,
                          QGpgME::CryptoConfigEntry *entry,
                          const QString &entryName,
                          QGridLayout *layout,
                          QWidget *parent = nullptr);

    void doSave() override;
    void doLoad() override;
private:
    Kleo::FileNameRequester *mFileNameRequester = nullptr;
};

/**
 * A widget manager for a directory path entry in the crypto config
 */
class CryptoConfigEntryDirPath : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntryDirPath(CryptoConfigModule *module,
                             QGpgME::CryptoConfigEntry *entry,
                             const QString &entryName,
                             QGridLayout *layout,
                             QWidget *parent = nullptr);

    void doSave() override;
    void doLoad() override;
private:
    Kleo::FileNameRequester *mFileNameRequester = nullptr;
};

/**
 * A widget manager for an int/uint entry in the crypto config
 */
class CryptoConfigEntrySpinBox : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntrySpinBox(CryptoConfigModule *module,
                             QGpgME::CryptoConfigEntry *entry,
                             const QString &entryName,
                             QGridLayout *layout,
                             QWidget *parent = nullptr);
    void doSave() override;
    void doLoad() override;
private:
    enum { Int, UInt, ListOfNone } mKind;
    QSpinBox *mNumInput = nullptr;
};

/**
 * A widget manager for a bool entry in the crypto config
 */
class CryptoConfigEntryCheckBox : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntryCheckBox(CryptoConfigModule *module,
                              QGpgME::CryptoConfigEntry *entry,
                              const QString &entryName,
                              QGridLayout *layout,
                              QWidget *parent = nullptr);
    void doSave() override;
    void doLoad() override;
private:
    QCheckBox *mCheckBox = nullptr;
};

/**
 * A widget manager for an LDAP list entry in the crypto config
 */
class CryptoConfigEntryLDAPURL : public CryptoConfigEntryGUI
{
    Q_OBJECT

public:
    CryptoConfigEntryLDAPURL(CryptoConfigModule *module,
                             QGpgME::CryptoConfigEntry *entry,
                             const QString &entryName,
                             QGridLayout *layout,
                             QWidget *parent = nullptr);
    void doSave() override;
    void doLoad() override;
private Q_SLOTS:
    void slotOpenDialog();
private:
    void setURLList(const QList<QUrl> &urlList);
    QLabel *mLabel = nullptr;
    QPushButton *mPushButton = nullptr;
    QList<QUrl> mURLList;
};

}

