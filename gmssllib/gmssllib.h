#ifndef GMSSLLIB_H
#define GMSSLLIB_H

#include <QObject>
#include <gmssl/sm2.h>
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/asn1.h>


class GmsslLib : public QObject
{
    Q_OBJECT
public:
    explicit GmsslLib(QObject *parent = nullptr);
    ~GmsslLib();

    // 加载 HEX 格式的公钥私钥
    // 参数 : pri 私钥， pub 公钥
    int loadKeyFormHex(const QString &pri, const QString &pub);
    // 单独加载公钥私钥
    int loadPrivateKey(const QString &pri);
    int loadPublicKey(const QString &pub);

    // 从 pem 文件加载公钥私钥
    int loadPrivateKeyFormPem(const QString &path);
    int loadPublicKeyFormPem(const QString &path);

    // 保存 hex 密钥到 pem 文件
    int savePrivateKeyToPem(const QString &path);
    int savePublicKeyToPem(const QString &path);

    // SM2 加密：将输入字符串加密成 ASN.1标准格式
    // 参数：plaintext 明文字符串
    // 返回值：HEX密文，失败则返回空
    QString sm2EncryptASN1(const QString &plaintext);
    // SM2 加密： 将输入字符串加密成 旧格式Hex
    QString sm2EncryptHex(const QString &plaintext);

    // SM2 解密
    // 参数： ASN.1 标准格式密文
    // 返回值：解密后的字符串，失败则返回空
    QString sm2DecryptASN1(const QString &cipherHex);
    // SM2 解密， 适配旧格式 Hex
    QString sm2DecryptHex(const QString &cipherHex);


signals:


private slots:



private:




private:
    QString m_privateKey;
    QString m_publicKey;

    SM2_KEY m_sm2PriKey;
    SM2_KEY m_sm2PubKey;

    bool m_isKeyLoad = false;
};

#endif // GMSSLLIB_H
