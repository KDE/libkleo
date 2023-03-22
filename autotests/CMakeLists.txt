# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMAddTests)

find_package(Qt${QT_MAJOR_VERSION}Test ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT TARGET Qt::Test)
    message(STATUS "Qt${QT_MAJOR_VERSION}Test not found, autotests will not be built.")
    return()
endif()

ecm_add_test(
    flatkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    TEST_NAME flatkeylistmodeltest
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Qt::Test
)

ecm_add_test(
    hierarchicalkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    abstractkeylistmodeltest.h
    TEST_NAME hierarchicalkeylistmodeltest
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Qt::Test
)

ecm_add_test(
    keyresolvercoretest.cpp
    keyresolvercoretest.qrc
    TEST_NAME keyresolvercoretest
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Qt::Test
)

ecm_add_tests(
    editdirectoryservicedialogtest.cpp
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo KF${KF_MAJOR_VERSION}::WidgetsAddons Qt::Widgets Qt::Test
)

ecm_add_tests(
    keyselectioncombotest.cpp
    keyserverconfigtest.cpp
    newkeyapprovaldialogtest.cpp
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Qt::Widgets Qt::Test
)

ecm_add_test(
    expirycheckertest.cpp
    expirycheckertest.qrc
    TEST_NAME expirycheckertest
    LINK_LIBRARIES
        KPim${KF_MAJOR_VERSION}::Libkleo
        Qt::Test
)

ecm_add_tests(
    hextest.cpp
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Qt::Test
)
