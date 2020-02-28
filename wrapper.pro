TEMPLATE=lib
TARGET=WrapperOpenSSL

SOURCES = \
    src/checksum.cpp \
    src/authentication.cpp \
    src/algorithm.cpp \
    src/authcomponent.cpp \
    src/algorithmmd5.cpp \
    src/algorithmsha1.cpp \
    src/algorithmsha256.cpp \
    src/algorithmsha1_hmac.cpp \    
    src/algorithmbuilder.cpp

HEADERS = \
    src/checksum.h \
    src/authentication.h \
    src/algorithm.h \
    src/authcomponent.h \
    src/algorithmmd5.h \
    src/algorithmsha1.h \
    src/algorithmsha256.h \
    src/algorithmsha1_hmac.h \
    src/algorithmbuilder.h

LIBS += -lssl

QMAKE_CXXFLAGS += -std=c++11
CONFIG += c++11
