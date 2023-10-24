/* -*- mode: c++; c-basic-offset:4 -*-
    utils/compliance.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <string_view>
#include <vector>

class QPushButton;
class QString;

namespace GpgME
{
class Key;
}

namespace Kleo::DeVSCompliance
{

/**
 * Returns true, if compliance mode "de-vs" is configured for GnuPG.
 * Note: It does not check whether the used GnuPG is actually compliant.
 */
KLEO_EXPORT bool isActive();

/**
 * Returns true, if compliance mode "de-vs" is configured for GnuPG and if
 * GnuPG passes a basic compliance check, i.e. at least libgcrypt and the used
 * RNG are compliant.
 */
KLEO_EXPORT bool isCompliant();

/**
 * Returns true, if the given algorithm is compliant with compliance mode
 * "de-vs". Always returns true, if compliance mode "de-vs" is not active.
 */
KLEO_EXPORT bool algorithmIsCompliant(std::string_view algo);

/**
 * Returns true, if all usable subkeys of the key \p key are compliant with
 * compliance mode "de-vs". Usable subkeys are those that are neither revoked
 * nor expired. If the key doesn't have any usable subkeys, then false is
 * returned.
 * Always returns true, if compliance mode "de-vs" is not active.
 */
KLEO_EXPORT bool allSubkeysAreCompliant(const GpgME::Key &key);

/**
 * Returns true, if the key \p key is compliant with compliance mode "de-vs".
 * A key is considered compliant if all usable subkeys are compliant and if
 * all not revoked user IDs have at least full validity. The second condition
 * requires that the key has been validated.
 * Always returns true, if compliance mode "de-vs" is not active.
 *
 * \see allSubkeysAreCompliant
 */
KLEO_EXPORT bool keyIsCompliant(const GpgME::Key &key);

/**
 * Returns a static list of the available compliant algorithms.
 */
KLEO_EXPORT const std::vector<std::string> &compliantAlgorithms();

/**
 * Returns a static list of the preferred compliant algorithms with decreasing
 * preference.
 * Can be used to determine the default algorithm for generating new keys.
 */
KLEO_EXPORT const std::vector<std::string> &preferredCompliantAlgorithms();

/**
 * \overload
 *
 * Sets the appropriate icon and, unless high-contrast mode is active, the
 * appropriate background color of \p button depending on the state of
 * compliance.
 */
KLEO_EXPORT void decorate(QPushButton *button);

/**
 * Sets the appropriate icon and, unless high-contrast mode is active, the
 * appropriate background color of \p button depending on the value of
 * \p compliant.
 */
KLEO_EXPORT void decorate(QPushButton *button, bool compliant);

/**
 * \overload
 *
 * Returns a localized name for the compliance or non-compliance depending on
 * the state of compliance.
 */
KLEO_EXPORT QString name();

/**
 * Returns a localized name for the compliance or non-compliance depending on
 * the value of \p compliant.
 *
 * \note The localized name is taken from the de-vs-filter filter resp. the
 * not-de-vs-filter. This allows the customization of the name for different
 * users because VS-NfD compliance is called differently in different
 * environments, e.g. NATO RESTRICTED or EU RESTRICTED.
 */
KLEO_EXPORT QString name(bool compliant);
}
