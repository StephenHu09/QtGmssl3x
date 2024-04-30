#include "gmssllib.h"

GmsslLib::GmsslLib(QObject *parent)
    : QObject{parent}
{}

GmsslLib::~GmsslLib()
{

}

int GmsslLib::loadKey(const QByteArray &sk, const QByteArray &pk)
{
    return 0;
}

QByteArray GmsslLib::sm2Encrypt(const QString &plaintext)
{
    return "";
}

QString GmsslLib::sm2Decrypt(const QByteArray &ciphertext)
{
    return "";
}
