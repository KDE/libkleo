/*
    autotests/keyselectioncombotest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeySelectionCombo>

#include <QSignalSpy>
#include <QTest>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <gpgme.h>

#include <memory>

using namespace Kleo;

namespace
{

auto mapValidity(GpgME::UserID::Validity validity)
{
    switch (validity) {
    default:
    case GpgME::UserID::Unknown: return GPGME_VALIDITY_UNKNOWN;
    case GpgME::UserID::Undefined: return GPGME_VALIDITY_UNDEFINED;
    case GpgME::UserID::Never: return GPGME_VALIDITY_NEVER;
    case GpgME::UserID::Marginal: return GPGME_VALIDITY_MARGINAL;
    case GpgME::UserID::Full: return GPGME_VALIDITY_FULL;
    case GpgME::UserID::Ultimate: return GPGME_VALIDITY_ULTIMATE;
    }
}

GpgME::Key createTestKey(const char *uid, GpgME::Protocol protocol = GpgME::UnknownProtocol, KeyUsage usage = KeyUsage::AnyUsage,
                         GpgME::UserID::Validity validity = GpgME::UserID::Full)
{
    static int count = 0;
    count++;

    gpgme_key_t key;
    gpgme_key_from_uid(&key, uid);
    Q_ASSERT(key);
    Q_ASSERT(key->uids);
    if (protocol != GpgME::UnknownProtocol) {
        key->protocol = protocol == GpgME::OpenPGP ? GPGME_PROTOCOL_OpenPGP : GPGME_PROTOCOL_CMS;
    }
    const QByteArray fingerprint = QByteArray::number(count, 16).rightJustified(40, '0');
    key->fpr = strdup(fingerprint.constData());
    key->revoked = 0;
    key->expired = 0;
    key->disabled = 0;
    key->can_encrypt = int(usage == KeyUsage::AnyUsage || usage == KeyUsage::Encrypt);
    key->can_sign = int(usage == KeyUsage::AnyUsage || usage == KeyUsage::Sign);
    key->secret = 1;
    key->uids->validity = mapValidity(validity);

    return GpgME::Key(key, false);
}

auto testKey(const char *address, GpgME::Protocol protocol = GpgME::UnknownProtocol)
{
    const auto email = GpgME::UserID::addrSpecFromString(address);
    const auto keys = KeyCache::instance()->findByEMailAddress(email);
    for (const auto &key: keys) {
        if (protocol == GpgME::UnknownProtocol || key.protocol() == protocol) {
            return key;
        }
    }
    return GpgME::Key();
}

void waitForKeySelectionComboBeingInitialized(const KeySelectionCombo *combo)
{
    QVERIFY(combo);

    const auto spy = std::make_unique<QSignalSpy>(combo, &KeySelectionCombo::keyListingFinished);
    QVERIFY(spy->isValid());
    QVERIFY(spy->wait(10));
}

}

class KeySelectionComboTest: public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init()
    {
        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();

        KeyCache::mutableInstance()->setKeys({
            createTestKey("sender@example.net", GpgME::OpenPGP, KeyUsage::AnyUsage),
            createTestKey("sender@example.net", GpgME::CMS, KeyUsage::AnyUsage),
            createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP, KeyUsage::Encrypt),
            createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS, KeyUsage::Encrypt),
            createTestKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP, KeyUsage::Encrypt, GpgME::UserID::Marginal),
        });
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();
    }

    void test__verify_test_keys()
    {
        QVERIFY(!testKey("sender@example.net", GpgME::OpenPGP).isNull());
        QVERIFY(!testKey("sender@example.net", GpgME::CMS).isNull());
        QVERIFY(!testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).isNull());
        QVERIFY(!testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS).isNull());
        QVERIFY(!testKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP).isNull());
    }

    void test__after_initialization_default_key_is_current_key()
    {
        const auto combo = std::make_unique<KeySelectionCombo>();
        combo->setDefaultKey(QString::fromLatin1(testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint()));
        waitForKeySelectionComboBeingInitialized(combo.get());

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint());
    }

    void test__currently_selected_key_is_retained_if_cache_is_updated()
    {
        const auto combo = std::make_unique<KeySelectionCombo>();
        combo->setDefaultKey(QString::fromLatin1(testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint()));
        waitForKeySelectionComboBeingInitialized(combo.get());

        combo->setCurrentIndex(3);

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS).primaryFingerprint());

        Q_EMIT KeyCache::mutableInstance()->keyListingDone(GpgME::KeyListResult{});

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS).primaryFingerprint());
    }

    void test__default_key_is_selected_if_currently_selected_key_is_gone_after_model_update()
    {
        const auto combo = std::make_unique<KeySelectionCombo>();
        combo->setDefaultKey(QString::fromLatin1(testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint()));
        waitForKeySelectionComboBeingInitialized(combo.get());

        combo->setCurrentIndex(3);

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS).primaryFingerprint());

        KeyCache::mutableInstance()->setKeys({
            testKey("sender@example.net", GpgME::OpenPGP),
            testKey("sender@example.net", GpgME::CMS),
            testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP),
            testKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP),
        });

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint());
    }

    void test__currently_selected_custom_item_is_retained_if_cache_is_updated()
    {
        const auto combo = std::make_unique<KeySelectionCombo>();
        combo->prependCustomItem({}, {}, QStringLiteral("custom1"));
        combo->appendCustomItem({}, {}, QStringLiteral("custom2"));
        combo->setDefaultKey(QString::fromLatin1(testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint()));
        waitForKeySelectionComboBeingInitialized(combo.get());

        combo->setCurrentIndex(combo->count() - 1);
        QCOMPARE(combo->currentData(), QStringLiteral("custom2"));

        Q_EMIT KeyCache::mutableInstance()->keyListingDone(GpgME::KeyListResult{});

        QCOMPARE(combo->currentData(), QStringLiteral("custom2"));
    }

    void test__default_key_is_selected_if_currently_selected_custom_item_is_gone_after_model_update()
    {
        const auto combo = std::make_unique<KeySelectionCombo>();
        combo->prependCustomItem({}, {}, QStringLiteral("custom1"));
        combo->appendCustomItem({}, {}, QStringLiteral("custom2"));
        combo->setDefaultKey(QString::fromLatin1(testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint()));
        waitForKeySelectionComboBeingInitialized(combo.get());

        combo->setCurrentIndex(combo->count() - 1);
        QCOMPARE(combo->currentData(), QStringLiteral("custom2"));

        combo->removeCustomItem(QStringLiteral("custom2"));

        QCOMPARE(combo->currentKey().primaryFingerprint(), testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).primaryFingerprint());
    }

private:
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(KeySelectionComboTest)
#include "keyselectioncombotest.moc"
