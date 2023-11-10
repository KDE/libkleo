# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
set(PIM_VERSION "5.240.81")

project(libkleo VERSION ${PIM_VERSION})

set(KF_MIN_VERSION "5.240.0")

if (WIN32)
  set(KF6_WANT_VERSION "5.104.0")
  add_compile_definitions(GPG_ERR_ENABLE_GETTEXT_MACROS=1)
else ()
  set(KF6_WANT_VERSION ${KF_MIN_VERSION})
endif ()

find_package(ECM ${KF6_WANT_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

include(ECMGenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)

include(FeatureSummary)
include(ECMQtDeclareLoggingCategory)
include(ECMDeprecationSettings)
include(ECMAddQch)
include(KDEClangFormat)
include(KDEGitCommitHooks)

option(BUILD_QCH "Build API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)" OFF)
add_feature_info(QCH ${BUILD_QCH} "API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)")

set(LIBKLEO_LIB_VERSION ${PIM_VERSION})
set(QT_REQUIRED_VERSION "6.5.0")
set(GPGME_REQUIRED_VERSION "1.20.0")
set(KTEXTADDONS_MIN_VERSION "1.5.1")
set(GPG_ERROR_REQUIRED_VERSION "1.36")

find_package(Qt6 ${QT_REQUIRED_VERSION} CONFIG REQUIRED Widgets)
find_package(Qt6Core5Compat)
find_package(KF6I18n ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6Config ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6WidgetsAddons ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6ColorScheme ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6Completion ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6CoreAddons ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6Codecs ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6ItemModels ${KF6_WANT_VERSION} CONFIG REQUIRED)
find_package(KF6TextCustomEditor ${KTEXTADDONS_MIN_VERSION} CONFIG)

find_package(Gpgmepp ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)
set_package_properties(Gpgmepp PROPERTIES DESCRIPTION "GpgME++ Library" URL "https://www.gnupg.org" TYPE REQUIRED PURPOSE "GpgME++ is required for OpenPGP support")
message(STATUS "GpgME++ Version ${Gpgmepp_VERSION}")
set(QGPGME_NAME "QGpgmeQt6")
if (Gpgmepp_VERSION VERSION_GREATER_EQUAL "1.23.0")
    set(GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE 1)
endif()
find_package(${QGPGME_NAME} ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)

find_package(LibGpgError ${GPG_ERROR_REQUIRED_VERSION} REQUIRED)
set_package_properties(LibGpgError PROPERTIES
  TYPE REQUIRED
)

find_package(Boost 1.34.0)
set_package_properties(Boost PROPERTIES DESCRIPTION "Boost C++ Libraries" URL "https://www.boost.org" TYPE REQUIRED PURPOSE "Boost is required for building most KDEPIM applications")


set_package_properties(KPim6TextEdit PROPERTIES DESCRIPTION
                       "A textedit with PIM-specific features."
                       URL "https://commits.kde.org/kpimtextedit"
                       TYPE OPTIONAL PURPOSE "Improved audit log viewer.")

ecm_setup_version(PROJECT VARIABLE_PREFIX LIBKLEO
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KPim6LibkleoConfigVersion.cmake"
                        SOVERSION 6
)

########### Targets ###########
ecm_set_disabled_deprecation_versions(QT 5.15.2  KF 5.240.0)

remove_definitions(-DQT_NO_FOREACH)
add_definitions(-DQT_NO_EMIT)
########### CMake Config Files ###########
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KPim6Libkleo")


install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h
  DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/Libkleo COMPONENT Devel
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config-libkleo.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-libkleo.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

option(USE_UNITY_CMAKE_SUPPORT "Use UNITY cmake support (speedup compile time)" OFF)

set(COMPILE_WITH_UNITY_CMAKE_SUPPORT OFF)
if (USE_UNITY_CMAKE_SUPPORT)
    set(COMPILE_WITH_UNITY_CMAKE_SUPPORT ON)
endif()


add_subdirectory(src)
if (BUILD_TESTING)
    add_subdirectory(autotests)
    add_subdirectory(tests)
endif()

ecm_qt_install_logging_categories(
        EXPORT LIBKLEO
        FILE libkleo.categories
        DESTINATION ${KDE_INSTALL_LOGGINGCATEGORIESDIR}
        )

ki18n_install(po)
if (BUILD_QCH)
    ecm_install_qch_export(
        TARGETS KPim6Libkleo_QCH
        FILE KPim6LibkleoQchTargets.cmake
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
    )
    set(PACKAGE_INCLUDE_QCHTARGETS "include(\"\${CMAKE_CURRENT_LIST_DIR}/KPim6LibkleoQchTargets.cmake\")")
endif()

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KPimLibkleoConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LibkleoConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LibkleoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim6LibkleoConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(EXPORT KPim6LibkleoTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KPim6LibkleoTargets.cmake NAMESPACE KPim6::)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)

# add clang-format target for all our real source files
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES *.cpp *.h *.c)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})
kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)

