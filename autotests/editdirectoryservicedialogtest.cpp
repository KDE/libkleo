/*
    autotests/editdirectoryservicedialogtest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/EditDirectoryServiceDialog>
#include <Libkleo/KeyserverConfig>

#include <KCollapsibleGroupBox>
#include <KPasswordLineEdit>

#include <QButtonGroup>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QList>
#include <QObject>
#include <QPushButton>
#include <QSpinBox>
#include <QTest>
#include <QWidget>

#include <memory>

using namespace Kleo;

namespace QTest
{
template <>
char *toString(const KeyserverAuthentication &authentication)
{
    return QTest::toString(static_cast<int>(authentication));
}

template <>
char *toString(const KeyserverConnection &connection)
{
    return QTest::toString(static_cast<int>(connection));
}
}

#define ASSERT_HOST_IS( expected ) \
do { \
    const auto w = dialog->findChild<QLineEdit *>(QStringLiteral("hostEdit")); \
    QVERIFY(w); \
    QCOMPARE(w->text(), expected); \
} while (false)

#define ASSERT_PORT_IS( expected ) \
do { \
    const auto w = dialog->findChild<QSpinBox *>(QStringLiteral("portSpinBox")); \
    QVERIFY(w); \
    QCOMPARE(w->value(), expected); \
} while (false)

#define ASSERT_USE_DEFAULT_PORT_IS( expected ) \
do { \
    const auto w = dialog->findChild<QCheckBox *>(QStringLiteral("useDefaultPortCheckBox")); \
    QVERIFY(w); \
    QCOMPARE(w->isChecked(), expected); \
} while (false)

#define ASSERT_AUTHENTICATION_IS( expected ) \
do { \
    const auto w = dialog->findChild<QButtonGroup *>(QStringLiteral("authenticationGroup")); \
    QVERIFY(w); \
    QCOMPARE(w->checkedId(), static_cast<int>(expected)); \
} while (false)

#define ASSERT_USER_IS( expected ) \
do { \
    const auto w = dialog->findChild<QLineEdit *>(QStringLiteral("userEdit")); \
    QVERIFY(w); \
    QCOMPARE(w->text(), expected); \
} while (false)

#define ASSERT_PASSWORD_IS( expected ) \
do { \
    const auto w = dialog->findChild<KPasswordLineEdit *>(QStringLiteral("passwordEdit")); \
    QVERIFY(w); \
    QCOMPARE(w->password(), expected); \
} while (false)

#define ASSERT_CONNECTION_IS( expected ) \
do { \
    const auto w = dialog->findChild<QButtonGroup *>(QStringLiteral("connectionGroup")); \
    QVERIFY(w); \
    QCOMPARE(w->checkedId(), static_cast<int>(expected)); \
} while (false)

#define ASSERT_BASE_DN_IS( expected ) \
do { \
    const auto w = dialog->findChild<QLineEdit *>(QStringLiteral("baseDnEdit")); \
    QVERIFY(w); \
    QCOMPARE(w->text(), expected); \
} while (false)

#define ASSERT_ADDITONAL_FLAGS_ARE( expected ) \
do { \
    const auto w = dialog->findChild<QLineEdit *>(QStringLiteral("additionalFlagsEdit")); \
    QVERIFY(w); \
    QCOMPARE(w->text(), expected); \
} while (false)

#define ASSERT_WIDGET_IS_ENABLED( objectName ) \
do { \
    const auto w = dialog->findChild<QWidget *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    QVERIFY(w->isEnabled()); \
} while (false)

#define ASSERT_WIDGET_IS_DISABLED( objectName ) \
do { \
    const auto w = dialog->findChild<QWidget *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    QVERIFY(!w->isEnabled()); \
} while (false)

#define ASSERT_ADVANCED_SETTINGS_ARE_EXPANDED() \
do { \
    const auto w = dialog->findChild<KCollapsibleGroupBox *>(QStringLiteral("advancedSettings")); \
    QVERIFY(w); \
    QVERIFY(w->isExpanded()); \
} while (false)

#define ASSERT_ADVANCED_SETTINGS_ARE_COLLAPSED() \
do { \
    const auto w = dialog->findChild<KCollapsibleGroupBox *>(QStringLiteral("advancedSettings")); \
    QVERIFY(w); \
    QVERIFY(!w->isExpanded()); \
} while (false)

#define ASSERT_OK_BUTTON_IS_ENABLED() \
do { \
    const auto o = dialog->findChild<QDialogButtonBox *>(QStringLiteral("buttonBox")); \
    QVERIFY(o); \
    QVERIFY(o->button(QDialogButtonBox::Ok)); \
    QVERIFY(o->button(QDialogButtonBox::Ok)->isEnabled()); \
} while (false)

#define ASSERT_OK_BUTTON_IS_DISABLED() \
do { \
    const auto o = dialog->findChild<QDialogButtonBox *>(QStringLiteral("buttonBox")); \
    QVERIFY(o); \
    QVERIFY(o->button(QDialogButtonBox::Ok)); \
    QVERIFY(!o->button(QDialogButtonBox::Ok)->isEnabled()); \
} while (false)

#define WHEN_USER_SETS_LINEEDIT_VALUE_TO( objectName, value ) \
do { \
    const auto w = dialog->findChild<QLineEdit *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    w->selectAll(); \
    w->del(); \
    QTest::keyClicks(w, value); \
} while (false)

#define WHEN_USER_SETS_PASSWORD_TO( objectName, value ) \
do { \
    const auto w = dialog->findChild<KPasswordLineEdit *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    w->setPassword(value); \
} while (false)

#define WHEN_USER_TOGGLES_BUTTON( objectName ) \
do { \
    const auto w = dialog->findChild<QAbstractButton *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    QVERIFY(w->isCheckable()); \
    w->toggle(); \
} while (false)

#define WHEN_USER_SETS_SPINBOX_VALUE_TO( objectName, value ) \
do { \
    const auto w = dialog->findChild<QSpinBox *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    w->setValue(value); \
} while (false)

#define WHEN_USER_SELECTS_BUTTON_WITH_ID_IN_BUTTON_GROUP( objectName, buttonId ) \
do { \
    const auto w = dialog->findChild<QButtonGroup *>(QStringLiteral(objectName)); \
    QVERIFY(w); \
    const auto button = w->button(buttonId); \
    QVERIFY(button); \
    button->setChecked(true); \
} while (false)

#define WHEN_USER_SELECTS_AUTHENTICATION( authentication ) \
    WHEN_USER_SELECTS_BUTTON_WITH_ID_IN_BUTTON_GROUP("authenticationGroup", static_cast<int>(authentication));

#define WHEN_USER_SELECTS_CONNECTION( connection ) \
    WHEN_USER_SELECTS_BUTTON_WITH_ID_IN_BUTTON_GROUP("connectionGroup", static_cast<int>(connection));

class EditDirectoryServiceDialogTest: public QObject
{
    Q_OBJECT

private:
    std::unique_ptr<EditDirectoryServiceDialog> dialog;

private Q_SLOTS:
    void init()
    {
        dialog = std::make_unique<EditDirectoryServiceDialog>();
    }

    void cleanup()
    {
        dialog.reset();
    }

    void test__initialization()
    {
        dialog->show();

        ASSERT_HOST_IS("");
        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_WIDGET_IS_DISABLED("portSpinBox");
        ASSERT_PORT_IS(389);
        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Anonymous);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_USER_IS("");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
        ASSERT_PASSWORD_IS("");
        ASSERT_CONNECTION_IS(KeyserverConnection::Default);
        ASSERT_ADVANCED_SETTINGS_ARE_COLLAPSED();
        ASSERT_BASE_DN_IS("");
        ASSERT_ADDITONAL_FLAGS_ARE("");
        ASSERT_OK_BUTTON_IS_DISABLED();
    }

    void test__setKeyserver_new_server()
    {
        KeyserverConfig keyserver;

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_HOST_IS("");
        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_WIDGET_IS_DISABLED("portSpinBox");
        ASSERT_PORT_IS(389);
        ASSERT_AUTHENTICATION_IS(keyserver.authentication());
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_USER_IS("");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
        ASSERT_PASSWORD_IS("");
        ASSERT_CONNECTION_IS(keyserver.connection());
        ASSERT_ADVANCED_SETTINGS_ARE_COLLAPSED();
        ASSERT_BASE_DN_IS("");
        ASSERT_ADDITONAL_FLAGS_ARE("");
        ASSERT_OK_BUTTON_IS_DISABLED();
    }

    void test__setKeyserver_existing_server()
    {
        KeyserverConfig keyserver;
        keyserver.setHost(QStringLiteral("ldap.example.com"));

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_HOST_IS("ldap.example.com");
        ASSERT_OK_BUTTON_IS_ENABLED();
    }

    void test__setKeyserver_anonymous_ldap_server()
    {
        KeyserverConfig keyserver;
        keyserver.setAuthentication(KeyserverAuthentication::Anonymous);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Anonymous);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
    }

    void test__setKeyserver_authentication_via_active_directory()
    {
        KeyserverConfig keyserver;
        keyserver.setAuthentication(KeyserverAuthentication::ActiveDirectory);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::ActiveDirectory);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
    }

    void test__setKeyserver_authentication_with_password()
    {
        KeyserverConfig keyserver;
        keyserver.setHost(QStringLiteral("ldap.example.com"));
        keyserver.setAuthentication(KeyserverAuthentication::Password);
        keyserver.setUser(QStringLiteral("bind dn"));
        keyserver.setPassword(QStringLiteral("abc123"));

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Password);
        ASSERT_WIDGET_IS_ENABLED("userEdit");
        ASSERT_USER_IS("bind dn");
        ASSERT_WIDGET_IS_ENABLED("passwordEdit");
        ASSERT_PASSWORD_IS("abc123");
        ASSERT_OK_BUTTON_IS_ENABLED();
    }

    void test__setKeyserver_authentication_with_password_requires_user()
    {
        KeyserverConfig keyserver;
        keyserver.setHost(QStringLiteral("ldap.example.com"));
        keyserver.setAuthentication(KeyserverAuthentication::Password);
        keyserver.setPassword(QStringLiteral("abc123"));

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Password);
        ASSERT_USER_IS("");
        ASSERT_PASSWORD_IS("abc123");
        ASSERT_OK_BUTTON_IS_DISABLED();
    }

    void test__setKeyserver_authentication_with_password_requires_password()
    {
        KeyserverConfig keyserver;
        keyserver.setHost(QStringLiteral("ldap.example.com"));
        keyserver.setAuthentication(KeyserverAuthentication::Password);
        keyserver.setUser(QStringLiteral("bind dn"));

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Password);
        ASSERT_USER_IS("bind dn");
        ASSERT_PASSWORD_IS("");
        ASSERT_OK_BUTTON_IS_DISABLED();
    }

    void test__setKeyserver_plain_connection()
    {
        KeyserverConfig keyserver;
        keyserver.setConnection(KeyserverConnection::Plain);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_PORT_IS(389);
        ASSERT_CONNECTION_IS(KeyserverConnection::Plain);
    }

    void test__setKeyserver_starttls_connection()
    {
        KeyserverConfig keyserver;
        keyserver.setConnection(KeyserverConnection::UseSTARTTLS);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_PORT_IS(389);
        ASSERT_CONNECTION_IS(KeyserverConnection::UseSTARTTLS);
    }

    void test__setKeyserver_ldaptls_connection()
    {
        KeyserverConfig keyserver;
        keyserver.setConnection(KeyserverConnection::TunnelThroughTLS);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_PORT_IS(636);
        ASSERT_CONNECTION_IS(KeyserverConnection::TunnelThroughTLS);
    }

    void test__setKeyserver_non_default_port()
    {
        KeyserverConfig keyserver;
        keyserver.setPort(1234);

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_USE_DEFAULT_PORT_IS(false);
        ASSERT_WIDGET_IS_ENABLED("portSpinBox");
        ASSERT_PORT_IS(1234);
    }

    void test__setKeyserver_base_dn()
    {
        KeyserverConfig keyserver;
        keyserver.setLdapBaseDn(QStringLiteral("o=Organization,c=DE"));

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_ADVANCED_SETTINGS_ARE_EXPANDED();
        ASSERT_BASE_DN_IS("o=Organization,c=DE");
    }

    void test__setKeyserver_additional_flags()
    {
        KeyserverConfig keyserver;
        keyserver.setAdditionalFlags({QStringLiteral("ldaps"), QStringLiteral("foo")});

        dialog->setKeyserver(keyserver);
        dialog->show();

        ASSERT_ADVANCED_SETTINGS_ARE_EXPANDED();
        ASSERT_ADDITONAL_FLAGS_ARE("ldaps,foo");
    }

    void test__user_sets_or_clears_host()
    {
        dialog->show();

        ASSERT_OK_BUTTON_IS_DISABLED();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("hostEdit", "ldap.example.com");
        ASSERT_OK_BUTTON_IS_ENABLED();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("hostEdit", "");
        ASSERT_OK_BUTTON_IS_DISABLED();
    }

    void test__user_enables_or_disables_use_of_default_port()
    {
        dialog->show();

        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_WIDGET_IS_DISABLED("portSpinBox");
        ASSERT_PORT_IS(389);

        WHEN_USER_TOGGLES_BUTTON("useDefaultPortCheckBox");
        ASSERT_WIDGET_IS_ENABLED("portSpinBox");
        ASSERT_PORT_IS(389);

        WHEN_USER_SETS_SPINBOX_VALUE_TO("portSpinBox", 1234);
        ASSERT_PORT_IS(1234);

        WHEN_USER_TOGGLES_BUTTON("useDefaultPortCheckBox");
        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_WIDGET_IS_DISABLED("portSpinBox");
        ASSERT_PORT_IS(389);
    }

    void test__user_changes_authentication()
    {
        dialog->show();
        WHEN_USER_SETS_LINEEDIT_VALUE_TO("hostEdit", "ldap.example.com");

        ASSERT_AUTHENTICATION_IS(KeyserverAuthentication::Anonymous);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
        ASSERT_OK_BUTTON_IS_ENABLED();

        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::ActiveDirectory);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
        ASSERT_OK_BUTTON_IS_ENABLED();

        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::Password);
        ASSERT_WIDGET_IS_ENABLED("userEdit");
        ASSERT_WIDGET_IS_ENABLED("passwordEdit");
        ASSERT_OK_BUTTON_IS_DISABLED();

        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::Anonymous);
        ASSERT_WIDGET_IS_DISABLED("userEdit");
        ASSERT_WIDGET_IS_DISABLED("passwordEdit");
        ASSERT_OK_BUTTON_IS_ENABLED();
    }

    void test__user_changes_user_and_password()
    {
        dialog->show();
        WHEN_USER_SETS_LINEEDIT_VALUE_TO("hostEdit", "ldap.example.com");
        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::Password);

        ASSERT_WIDGET_IS_ENABLED("userEdit");
        ASSERT_WIDGET_IS_ENABLED("passwordEdit");
        ASSERT_OK_BUTTON_IS_DISABLED();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("userEdit", "user");
        ASSERT_OK_BUTTON_IS_DISABLED();

        WHEN_USER_SETS_PASSWORD_TO("passwordEdit", "abc123");
        ASSERT_OK_BUTTON_IS_ENABLED();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("userEdit", "");
        ASSERT_OK_BUTTON_IS_DISABLED();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("userEdit", "user");
        ASSERT_OK_BUTTON_IS_ENABLED();
    }

    void test__user_changes_connection()
    {
        dialog->show();

        ASSERT_CONNECTION_IS(KeyserverConnection::Default);
        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_PORT_IS(389);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::TunnelThroughTLS);
        ASSERT_PORT_IS(636);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::Plain);
        ASSERT_PORT_IS(389);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::TunnelThroughTLS);
        ASSERT_PORT_IS(636);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::UseSTARTTLS);
        ASSERT_PORT_IS(389);

        WHEN_USER_TOGGLES_BUTTON("useDefaultPortCheckBox");
        ASSERT_USE_DEFAULT_PORT_IS(false);
        WHEN_USER_SETS_SPINBOX_VALUE_TO("portSpinBox", 1234);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::TunnelThroughTLS);
        ASSERT_PORT_IS(1234);

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::UseSTARTTLS);
        ASSERT_PORT_IS(1234);

        WHEN_USER_TOGGLES_BUTTON("useDefaultPortCheckBox");
        ASSERT_USE_DEFAULT_PORT_IS(true);
        ASSERT_PORT_IS(389);
    }

    void test__result()
    {
        dialog->show();

        WHEN_USER_SETS_LINEEDIT_VALUE_TO("hostEdit", "  ldap.example.com  ");
        QCOMPARE(dialog->keyserver().host(), "ldap.example.com");

        QCOMPARE(dialog->keyserver().port(), -1);
        WHEN_USER_TOGGLES_BUTTON("useDefaultPortCheckBox");
        QCOMPARE(dialog->keyserver().port(), 389);
        WHEN_USER_SETS_SPINBOX_VALUE_TO("portSpinBox", 1234);
        QCOMPARE(dialog->keyserver().port(), 1234);

        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::Anonymous);
        QCOMPARE(dialog->keyserver().authentication(), KeyserverAuthentication::Anonymous);
        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::ActiveDirectory);
        QCOMPARE(dialog->keyserver().authentication(), KeyserverAuthentication::ActiveDirectory);
        WHEN_USER_SELECTS_AUTHENTICATION(KeyserverAuthentication::Password);
        QCOMPARE(dialog->keyserver().authentication(), KeyserverAuthentication::Password);

        QCOMPARE(dialog->keyserver().user(), "");
        WHEN_USER_SETS_LINEEDIT_VALUE_TO("userEdit", "  user  ");
        QCOMPARE(dialog->keyserver().user(), "user");

        QCOMPARE(dialog->keyserver().password(), "");
        WHEN_USER_SETS_PASSWORD_TO("passwordEdit", "  abc123  ");
        QCOMPARE(dialog->keyserver().password(), "  abc123  "); // the entered password is not trimmed

        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::Default);
        QCOMPARE(dialog->keyserver().connection(), KeyserverConnection::Default);
        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::Plain);
        QCOMPARE(dialog->keyserver().connection(), KeyserverConnection::Plain);
        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::UseSTARTTLS);
        QCOMPARE(dialog->keyserver().connection(), KeyserverConnection::UseSTARTTLS);
        WHEN_USER_SELECTS_CONNECTION(KeyserverConnection::TunnelThroughTLS);
        QCOMPARE(dialog->keyserver().connection(), KeyserverConnection::TunnelThroughTLS);

        QCOMPARE(dialog->keyserver().ldapBaseDn(), "");
        WHEN_USER_SETS_LINEEDIT_VALUE_TO("baseDnEdit", "  o=Organization,c=DE  ");
        QCOMPARE(dialog->keyserver().ldapBaseDn(), "o=Organization,c=DE");

        QCOMPARE(dialog->keyserver().additionalFlags(), {});
        WHEN_USER_SETS_LINEEDIT_VALUE_TO("additionalFlagsEdit", "  flag1  ,  flag 2  ");
        const QStringList expectedFlags{"flag1", "flag 2"};
        QCOMPARE(dialog->keyserver().additionalFlags(), expectedFlags);
    }
};

QTEST_MAIN(EditDirectoryServiceDialogTest)
#include "editdirectoryservicedialogtest.moc"
