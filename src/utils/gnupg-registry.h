/* registry.h - registry prototypes
   SPDX-FileCopyrightText: 2006, 2007 g 10 Code GmbH

   This file is part of GpgEX.

   SPDX-License-Identifier: LGPL-2.0-or-later
*/

/* keep this in sync with svn://cvs.gnupg.org/gpgex/trunk/src/registry.h (last checked against rev. 19) */

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

/* This is a helper function to load a Windows function from either of
   one DLLs. */
HRESULT w32_shgetfolderpath(HWND a, int b, HANDLE c, DWORD d, LPSTR e);

/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
char *read_w32_registry_string(const char *root, const char *dir, const char *name);

#ifdef __cplusplus
#if 0
{
#endif
}
#endif
