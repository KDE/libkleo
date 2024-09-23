# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMAddTests)

find_package(Qt6Test ${QT_REQUIRED_VERSION} CONFIG QUIET)

if(NOT TARGET Qt::Test)
    message(STATUS "Qt6Test not found, autotests will not be built.")
    return()
endif()

ecm_add_test(
    flatkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    TEST_NAME flatkeylistmodeltest
    LINK_LIBRARIES KPim6::Libkleo Qt::Test
)

ecm_add_test(
    hierarchicalkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    abstractkeylistmodeltest.h
    TEST_NAME hierarchicalkeylistmodeltest
    LINK_LIBRARIES KPim6::Libkleo Qt::Test
)

ecm_add_test(
    keyresolvercoretest.cpp
    keyresolvercoretest.qrc
    TEST_NAME keyresolvercoretest
    LINK_LIBRARIES KPim6::Libkleo Qt::Test
)

ecm_add_tests(
    editdirectoryservicedialogtest.cpp
    LINK_LIBRARIES KPim6::Libkleo KF6::WidgetsAddons Qt::Widgets Qt::Test
)

ecm_add_tests(
    keyselectioncombotest.cpp
    keyserverconfigtest.cpp
    newkeyapprovaldialogtest.cpp
    LINK_LIBRARIES KPim6::Libkleo Qt::Widgets Qt::Test
)

ecm_add_test(
    expirycheckertest.cpp
    expirycheckertest.qrc
    testhelpers.h
    TEST_NAME expirycheckertest
    LINK_LIBRARIES
        KPim6::Libkleo
        Qt::Test
)

ecm_add_tests(
    hextest.cpp
    LINK_LIBRARIES KPim6::Libkleo Qt::Test
)

ecm_add_test(
    classifytest.cpp
    LINK_LIBRARIES
        KPim6::Libkleo
        Qt::Test
)

ecm_add_tests(
    formattingtest.cpp
    LINK_LIBRARIES KPim6::Libkleo Qt::Test
)

ecm_add_test(
    keyparameterstest.cpp
    TEST_NAME keyparameterstest
    LINK_LIBRARIES KPim6::Libkleo Gpgmepp Qt::Test
)
