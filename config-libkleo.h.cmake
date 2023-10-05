/* Defined if QGpgME::ListAllKeysJob supports setting options */
#cmakedefine QGPGME_LISTALLKEYSJOB_HAS_OPTIONS 1

/* Defined if Key::canSign should be used instead of deprecated Key::canReallySign */
#cmakedefine01 GPGMEPP_KEY_CANSIGN_IS_FIXED

/* Whether Error::asString() returns UTF-8 encoded strings on Windows */
#cmakedefine01 GPGMEPP_ERROR_ASSTRING_RETURNS_UTF8_ON_WINDOWS

/* Whether Key::hasCertify(), Key::hasSign(), Key::hasEncrypt(), Key::hasAuthenticate() exist */
#cmakedefine01 GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
