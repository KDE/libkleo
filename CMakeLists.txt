# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
set(PIM_VERSION "5.24.49")

project(libkleo VERSION ${PIM_VERSION})

set(KF_MIN_VERSION "5.105.0")

if (WIN32)
  set(KF5_WANT_VERSION "5.104.0")
else ()
  set(KF5_WANT_VERSION ${KF_MIN_VERSION})
endif ()

find_package(ECM ${KF5_WANT_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

include(ECMGenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(ECMGeneratePriFile)

include(FeatureSummary)
include(ECMQtDeclareLoggingCategory)
include(ECMDeprecationSettings)
include(ECMAddQch)
include(KDEClangFormat)
include(KDEGitCommitHooks)
option(BUILD_WITH_COMPAT_LIBS "Generate compat cmake file (Set at false will allow to co-install lib)" ON)

option(BUILD_QCH "Build API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)" OFF)
add_feature_info(QCH ${BUILD_QCH} "API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)")

set(LIBKLEO_LIB_VERSION ${PIM_VERSION})
set(QT_REQUIRED_VERSION "5.15.2")
if (QT_MAJOR_VERSION STREQUAL "6")
    set(QT_REQUIRED_VERSION "6.4.0")
    set(KF_MIN_VERSION "5.240.0")
    set(KF_MAJOR_VERSION "6")
else()
    set(KF_MAJOR_VERSION "5")
endif()

set(KDEPIMTEXTEDIT_VERSION "5.24.0")
set(GPGME_REQUIRED_VERSION "1.20.0")

find_package(Qt${QT_MAJOR_VERSION} ${QT_REQUIRED_VERSION} CONFIG REQUIRED Widgets)
if (QT_MAJOR_VERSION STREQUAL "6")
    find_package(Qt6Core5Compat)
endif()
find_package(KF${KF_MAJOR_VERSION}I18n ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}Config ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}WidgetsAddons ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}ConfigWidgets ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}Completion ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}CoreAddons ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}Codecs ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KF${KF_MAJOR_VERSION}ItemModels ${KF5_WANT_VERSION} CONFIG REQUIRED)
find_package(KPim${KF_MAJOR_VERSION}TextEdit ${KDEPIMTEXTEDIT_VERSION} CONFIG)

find_package(Gpgmepp ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)
set_package_properties(Gpgmepp PROPERTIES DESCRIPTION "GpgME++ Library" URL "https://www.gnupg.org" TYPE REQUIRED PURPOSE "GpgME++ is required for OpenPGP support")
message(STATUS "GpgME++ Version ${Gpgmepp_VERSION}")
if (Gpgmepp_VERSION VERSION_GREATER_EQUAL "1.23.0")
    set(GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE 1)
endif()
set(QGPGME_NAME "QGpgme")
find_package(${QGPGME_NAME} ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)

find_package(Boost 1.34.0)
set_package_properties(Boost PROPERTIES DESCRIPTION "Boost C++ Libraries" URL "https://www.boost.org" TYPE REQUIRED PURPOSE "Boost is required for building most KDEPIM applications")


set_package_properties(KPim${KF_MAJOR_VERSION}TextEdit PROPERTIES DESCRIPTION
                       "A textedit with PIM-specific features."
                       URL "https://commits.kde.org/kpimtextedit"
                       TYPE OPTIONAL PURPOSE "Improved audit log viewer.")

ecm_setup_version(PROJECT VARIABLE_PREFIX LIBKLEO
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoConfigVersion.cmake"
                        SOVERSION 5
)

########### Targets ###########
ecm_set_disabled_deprecation_versions(QT 5.15.2  KF 5.105.0)

remove_definitions(-DQT_NO_FOREACH)
add_definitions(-DQT_NO_EMIT)
########### CMake Config Files ###########
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KPim${KF_MAJOR_VERSION}Libkleo")
set(LIBKLEO_KF5_COMPAT FALSE)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KPimLibkleoConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(EXPORT KPim${KF_MAJOR_VERSION}LibkleoTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KPim${KF_MAJOR_VERSION}LibkleoTargets.cmake NAMESPACE KPim${KF_MAJOR_VERSION}::)

install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h
  DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim${KF_MAJOR_VERSION}/Libkleo COMPONENT Devel
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config-libkleo.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config-libkleo.h)
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
        TARGETS KPim${KF_MAJOR_VERSION}Libkleo_QCH
        FILE KPim${KF_MAJOR_VERSION}LibkleoQchTargets.cmake
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
    )
    set(PACKAGE_INCLUDE_QCHTARGETS "include(\"\${CMAKE_CURRENT_LIST_DIR}/KPim${KF_MAJOR_VERSION}LibkleoQchTargets.cmake\")")
endif()
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)

# add clang-format target for all our real source files
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES *.cpp *.h *.c)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})
kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)

if (BUILD_WITH_COMPAT_LIBS)
#if (QT_MAJOR_VERSION STREQUAL "5")
##
# TODO: Backwards compatiblity. Remove in next major version
##
set(CMAKECONFIG_INSTALL_DIR_KF5 "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Libkleo")
set(LIBKLEO_KF5_COMPAT TRUE)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/KPimLibkleoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfig.cmake"
    INSTALL_DESTINATION ${CMAKECONFIG_INSTALL_DIR_KF5}
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfig.cmake"
    DESTINATION "${CMAKECONFIG_INSTALL_DIR_KF5}"
    COMPONENT Devel
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoConfigVersion.cmake"
    RENAME "KF5LibkleoConfigVersion.cmake"
    DESTINATION "${CMAKECONFIG_INSTALL_DIR_KF5}"
    COMPONENT Devel
)
install(EXPORT KPim${KF_MAJOR_VERSION}LibkleoTargets
    DESTINATION "${CMAKECONFIG_INSTALL_DIR_KF5}"
    FILE KPim${KF_MAJOR_VERSION}LibkleoTargets.cmake
    NAMESPACE KF5::
)
if (BUILD_QCH)
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/KPim${KF_MAJOR_VERSION}LibkleoQchTargets.cmake"
        DESTINATION "${CMAKECONFIG_INSTALL_DIR_KF5}"
        COMPONENT Devel
    )
endif()
#endif()
endif()
