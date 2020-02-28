QT += core
QT -= gui

QMAKE_CXXFLAGS += -std=c++11
CONFIG += c++11

INCLUDEPATH += ../src

TARGET = unit_test
TEMPLATE = app

CONFIG += console
CONFIG -= app_bundle

LIBS += -lpthread
LIBS += -lssl
LIBS += -lcrypto

LIBS += /usr/src/gtest/src/libgtest.a
LIBS += /usr/src/gtest/src/libgtest_main.a

LIBS += /usr/src/gmock/libgmock.a
LIBS += /usr/src/gmock/libgmock_main.a

SOURCES = ./main.cpp \
    ../src/checksum.cpp \
    ../src/authentication.cpp \
    ../src/algorithm.cpp \
    ../src/authcomponent.cpp \
    ../src/algorithmmd5.cpp \
    ../src/algorithmsha1.cpp \
    ../src/algorithmsha256.cpp \
    ../src/algorithmsha1_hmac.cpp \
    ../src/algorithmbuilder.cpp

HEADERS = \
    ../src/checksum.h \
    ../src/authentication.h \
    ../src/algorithm.h \
    ../src/authcomponent.h \
    ../src/algorithmmd5.h \
    ../src/algorithmsha1.h \
    ../src/algorithmsha256.h \
    ../src/algorithmsha1_hmac.h \
    ../src/algorithmbuilder.h

