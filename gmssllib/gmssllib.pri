#gmssl lib module source for qt

INCLUDEPATH += $$PWD/
INCLUDEPATH += $$PWD/include/
DEPENDPATH += $$PWD


HEADERS += \
    $$PWD/include/gmssl/sm2.h \
    $$PWD/include/gmssl/sm2_z256.h \
    $$PWD/include/gmssl/asn1.h \
    $$PWD/include/gmssl/pem.h \
    $$PWD/include/gmssl/sm3.h \
    $$PWD/include/gmssl/sm4.h \
    $$PWD/include/gmssl/base64.h \
    $$PWD/include/gmssl/rand.h \
    $$PWD/include/gmssl/x509_alg.h \
    $$PWD/include/gmssl/mem.h

SOURCES += \
    $$PWD/gmssllib.cpp \
    $$PWD/src/sm2_key.c \
    $$PWD/src/sm2_enc.c \
    $$PWD/src/sm2_z256.c \
    $$PWD/src/asn1.c \
    $$PWD/src/pem.c \
    $$PWD/src/hex.c \
    $$PWD/src/sm3.c \
    $$PWD/src/sm4.c \
    $$PWD/src/sm4_cbc.c \
    $$PWD/src/base64.c \
    $$PWD/src/sm3_pbkdf2.c \
    $$PWD/src/rand_unix.c \
    $$PWD/src/pkcs8.c \
    $$PWD/src/ec.c \
    $$PWD/src/debug.c \
    $$PWD/src/x509_alg.c \
    $$PWD/src/sm2_z256_table.c \
    $$PWD/src/sm3_hmac.c \


HEADERS += \
    $$PWD/gmssllib.h

SOURCES += \
    $$PWD/gmssllib.cpp
