#include "gmssllib.h"

GmsslLib::GmsslLib(QObject *parent)
    : QObject{parent}
{}

GmsslLib::~GmsslLib()
{

}

int GmsslLib::loadKey(const QByteArray &sk, const QByteArray &pk)
{
    // m_privateKey = sk;
    // m_publicKey = pk;

#if 0
    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "04298364ec840088475eae92a591e01284d1abefcda348b47eb324bb521bb03b0b2a5bc393f6b71dabb8f15c99a0050818b56b23f31743b93df9cf8948f15ddb54";

    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "3037723d47292171677ec8bd7dc9af696c7472bc5f251b2cec07e65fdef22e25";
#endif

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
