#include "gmssllib.h"

#include <QFile>
#include <QDebug>

GmsslLib::GmsslLib(QObject *parent)
    : QObject{parent}
{

}

GmsslLib::~GmsslLib()
{
    gmssl_secure_clear(&m_sm2PriKey, sizeof(m_sm2PriKey));
    gmssl_secure_clear(&m_sm2PubKey, sizeof(m_sm2PubKey));
}

int GmsslLib::loadKeyFormHex(const QString &pri, const QString &pub)
{
    // 如何将 HEX 十六进制字符串格式的公钥和私钥转成pem格式的base64内容：
    // 1. 首先用 include/gmssl/hex.h 中的 hex_to_bytes 将公钥或者私钥转换成字节序列
    // 2. 然后用 sm2_key_set_public_key 或 sm2_key_set_private_key 将其转化为 SM2_KEY 类型
    // 3. 然后用 sm2_public_key_info_to_pem 或 sm2_private_key_info_encrypt_to_pem 将 SM2_KEY 写入PEM文

    if (loadPrivateKey(pri) != 0) {
        return -1;
    }
    if (savePrivateKeyToPem("sm2_prikey.pem") != 0) {
        return -1;
    }

    if (loadPublicKey(pub) != 0) {
        return -1;
    }
    if (savePublicKeyToPem("sm2_pubkey.pem") != 0) {
        return -1;
    }

    return 0;
}

int GmsslLib::loadPrivateKeyFormPem(const QString &path)
{
    if (path.isEmpty()) {
        return -1;
    }

    /* pem 密钥文件，可以先通过内部接口 savePrivateKeyToPem 和 savePublicKeyToPem 生成，
     * 也可以通过 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 网站将 HEX 密钥数据转化成pem格式，
     * 再保存为文件即可，不过两种方式的私钥pem文件格式有差异，对应加载解析接口不同，需要注意 */

    QString keyfile = path;
    QFile file(keyfile);
    if (!file.exists()) {
        qDebug() << "File does not exist:" << keyfile;
        return -1;
    }

    FILE *keyfp = fopen(keyfile.toStdString().c_str(), "rb"); // "r" 表示只读，可以根据需要更改
    if (!keyfp) {
        qDebug() << "Failed to open file:" << keyfile;
        return -1;
    }

    /*
     * 注： 使用网站 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 生成的 pem 文件格式数据，
     * 是 -----BEGIN EC PRIVATE KEY----- 格式的数据，
     * 需要使用 sm2_private_key_from_pem 接口进行加载才能正确解析
     */
    gmssl_secure_clear(&m_sm2PriKey, sizeof(m_sm2PriKey));
    if (sm2_private_key_info_from_pem(&m_sm2PriKey, keyfp) != 1) {
        qDebug() << "load key failure";
        fclose(keyfp);
        keyfp = nullptr;
        return -1;
    }

    qDebug() << "load private key success : " << keyfile;

    fclose(keyfp);
    keyfp = nullptr;

    return 0;
}

int GmsslLib::loadPublicKeyFormPem(const QString &path)
{

    QString pubkeyfile = "sm2_pubkey.pem";
    QFile pubfile(pubkeyfile);
    if (!pubfile.exists()) {
        qDebug() << "File does not exist:" << pubkeyfile;
        return -1;
    }

    FILE *pubkeyfp = fopen(pubkeyfile.toStdString().c_str(), "rb"); // "r" 表示只读，可以根据需要更改
    if (!pubkeyfp) {
        qDebug() << "Failed to open pubkeyfile :" << pubkeyfile;
        return -1;
    }

    if (sm2_public_key_info_from_pem(&m_sm2PubKey, pubkeyfp) != 1) {
        qDebug() << "load public key failure";
        fclose(pubkeyfp);
        pubkeyfp = nullptr;
        return -1;
    }

    qDebug() << "load public key success : " << pubkeyfile;

    fclose(pubkeyfp);
    pubkeyfp = nullptr;

    return 0;
}

QString GmsslLib::sm2EncryptASN1(const QString &plaintext)
{
    if (plaintext.isEmpty()) {
        return "";
    }

    unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    size_t len;

    QByteArray plainBytes = plaintext.toUtf8();

    int enRet = sm2_encrypt(&m_sm2PubKey,
                reinterpret_cast<uint8_t *>(plainBytes.data()), plainBytes.size(),
                ciphertext, &len);
    if (enRet != 1) {
        qDebug() << "sm2_encrypt failed ！！！";
        return "";
    }

    // 16进制格式 Str
    QByteArray cipherBytes(reinterpret_cast<const char*>(ciphertext), len);
    QString cipherHexStr = QString(cipherBytes.toHex());

#if 0
    // 方式二： 转化为 hex string
    // QString cipherHexStr;
    // for (int i = 0; i < len; ++i) {
    //     cipherHexStr.append(QString("%1").arg(ciphertext[i], 2, 16, QChar('0')));
    // }
#endif

    return cipherHexStr;
}

QString GmsslLib::sm2EncryptHex(const QString &plaintext)
{
    if (plaintext.isEmpty()) {
        return "";
    }

    QByteArray plainBytes = plaintext.toUtf8();

    // 转换格式
    SM2_CIPHERTEXT ctxt;
    int enRet2 = sm2_do_encrypt(&m_sm2PubKey, reinterpret_cast<uint8_t *>(plainBytes.data()), plainBytes.size(), &ctxt);
    if (enRet2 != 1) {
        qDebug() << "sm2_do_encrypt failed ！！！";
        return "";
    }

    QByteArray c1c3c2;
    // c1c3c2.append(static_cast<char>(0x04)); // 添加 04头, 根据需求选择是否添加，也可以在外部处理
    QByteArray x(reinterpret_cast<const char*>(ctxt.point.x), 32);  // SM2_POINT.x[32];
    QByteArray y(reinterpret_cast<const char*>(ctxt.point.y), 32);  // SM2_POINT.y[32];
    QByteArray hash(reinterpret_cast<const char*>(ctxt.hash), 32);  // SM2_CIPHERTEXT.hash[32]
    QByteArray cipherText1(reinterpret_cast<const char*>(ctxt.ciphertext), ctxt.ciphertext_size);

    c1c3c2.append(x);
    c1c3c2.append(y);
    c1c3c2.append(hash);
    c1c3c2.append(cipherText1);
    QString cipherHexStr2 = QString::fromUtf8(c1c3c2.toHex());

    return cipherHexStr2;
}

QString GmsslLib::sm2DecryptASN1(const QString &cipherHex)
{
    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    size_t len;

    QByteArray cipherBytes = QByteArray::fromHex(cipherHex.toUtf8());

    int deRet = sm2_decrypt(&m_sm2PriKey,
                reinterpret_cast<uint8_t *>(cipherBytes.data()), cipherBytes.size(),
                plaintext, &len);
    if (deRet != 1) {
        qDebug() << "sm2_decrypt failed ！！！";
        return "";
    }

    plaintext[len] = 0;
    QString plainStr = QString(QLatin1String(reinterpret_cast<const char*>(plaintext)));

    return plainStr;
}

QString GmsslLib::sm2DecryptHex(const QString &cipherHex)
{
    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    size_t len;

    QString cipherText = cipherHex;
    if (cipherText.startsWith("04")) {
        cipherText.remove(0, 2);
    }
    QByteArray cipherBytes = QByteArray::fromHex(cipherText.toUtf8());

    if (cipherBytes.size() < 96) {
        return "";
    }

    SM2_CIPHERTEXT cText;

    QByteArray xBytes = cipherBytes.mid(0, 32);
    QByteArray yBytes = cipherBytes.mid(xBytes.size(), 32);
    QByteArray hashBytes = cipherBytes.mid(xBytes.size() + yBytes.size(), 32);
    QByteArray ctBytes = cipherBytes.mid(xBytes.size() + yBytes.size() + hashBytes.size());

    // qDebug() << "bytes Len :" << cipherBytes.size()
    //          << ">>>  x, y, hash, ctxt =" << xBytes.size() << yBytes.size() << hashBytes.size() << ctBytes.size();

    memcpy(cText.point.x, xBytes.constData(), xBytes.size());
    memcpy(cText.point.y, yBytes.constData(), yBytes.size());
    memcpy(cText.hash, hashBytes.constData(), hashBytes.size());
    memcpy(cText.ciphertext, ctBytes.constData(), ctBytes.size());
    cText.ciphertext_size = ctBytes.size();

#if 0
    // TODO : sm2_ciphertext_from_der 接口调用, 结果不对，可能是类型转化有问题
    const uint8_t *cipherStr = reinterpret_cast<const uint8_t *>(cipherBytes.data());
    size_t cipherLen = cipherBytes.size();
    qDebug() << "cipherLen = " << cipherLen;
    if (sm2_ciphertext_from_der(&cText, &cipherStr, &cipherLen) != 1) {
        qDebug() << "get ciphertext from der failed ！！！";
        return "";
    }
#endif


    int deRet = sm2_do_decrypt(&m_sm2PriKey, &cText, plaintext, &len);
    if (deRet != 1) {
        qDebug() << "sm2_do_decrypt failed ！！！";
        return "";
    }

    plaintext[len] = 0;
    QString plainStr = QString(QLatin1String(reinterpret_cast<const char*>(plaintext)));

    return plainStr;
}

int GmsslLib::loadPrivateKey(const QString &pri)
{
    m_privateKey = pri;
    QByteArray ba = m_privateKey.toUtf8();
    const char *privateKey = ba.constData();

    uint8_t priBytes[32];
    size_t priLen;
    hex_to_bytes(privateKey, 64, priBytes, &priLen);

    gmssl_secure_clear(&m_sm2PriKey, sizeof(m_sm2PriKey));

    sm2_z256_t private_key;
    sm2_z256_from_bytes(private_key, priBytes);
    if (sm2_key_set_private_key(&m_sm2PriKey, private_key) != 1) {
        gmssl_secure_clear(private_key, 32);
        qDebug() << "load hex private key failed";
        return -1;
    }
    gmssl_secure_clear(private_key, 32);
    // qDebug() << "load hex private key success";

    return 0;
}

int GmsslLib::loadPublicKey(const QString &pub)
{
    m_publicKey = pub;

    QByteArray ba = m_publicKey.toUtf8();
    const char *publicKey = ba.constData();

    uint8_t pubBytes[64];
    size_t pubLen;
    hex_to_bytes(publicKey, 128, pubBytes, &pubLen);

    SM2_Z256_POINT point;
    if (sm2_z256_point_from_bytes(&point, pubBytes) != 1) {
        qDebug() << "load hex public key point failed";
        return -1;
    }

    gmssl_secure_clear(&m_sm2PubKey, sizeof(m_sm2PubKey));
    if (sm2_key_set_public_key(&m_sm2PubKey, &point) != 1) {
        qDebug() << "load hex public key failed";
        return -1;
    }
    // qDebug() << "load hex public key success";

    return 0;
}

int GmsslLib::savePrivateKeyToPem(const QString &path)
{
    if (path.isEmpty()) {
        return -1;
    }

    QString priKeyfile = path;
    QFile file(priKeyfile);
    FILE *prifp = fopen(priKeyfile.toStdString().c_str(), "w");
    if (!prifp) {
        qDebug() << "Failed to open file:" << priKeyfile;
        return -1; // 或者处理错误
    }

    // 注：sm2_private_key_to_pem 将生成 -----BEGIN EC PRIVATE KEY----- 格式的pem文件
    //    而 sm2_private_key_info_to_pem 接口生成的是 -----BEGIN PRIVATE KEY----- 格式的pem文件，
    //    相应的，使用不同接口生成的pem，也要使用对应的 from 接口进行解析，不然会不匹配报错。
    //    sm2_private_key_to_pem 对应 sm2_private_key_from_pem ；
    //    sm2_private_key_info_to_pem 对应 sm2_private_key_info_from_pem ；

    if (sm2_private_key_info_to_pem(&m_sm2PriKey, prifp) != 1) {
        qDebug() << "save private key pem failure";
        fclose(prifp);
        prifp = nullptr;
        return -1;
    }

    // qDebug() << "save private key pem success";

    fclose(prifp);
    prifp = nullptr;

    return 0;
}

int GmsslLib::savePublicKeyToPem(const QString &path)
{
    if (path.isEmpty()) {
        return -1;
    }

    QString pubKeyfile = path;
    QFile file(pubKeyfile);
    FILE *pubfp = fopen(pubKeyfile.toStdString().c_str(), "w");
    if (!pubfp) {
        qDebug() << "Failed to open file:" << pubKeyfile;
        return -1;
    }

    if (sm2_public_key_info_to_pem(&m_sm2PubKey, pubfp) != 1) {
        qDebug() << "save public key pem failure";
        fclose(pubfp);
        pubfp = nullptr;
        return -1;
    }

    // qDebug() << "save public key pem success";

    fclose(pubfp);
    pubfp = nullptr;

    return 0;
}
