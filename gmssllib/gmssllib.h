#ifndef GMSSLLIB_H
#define GMSSLLIB_H

#include <QObject>

class GmsslLib : public QObject
{
    Q_OBJECT
public:
    explicit GmsslLib(QObject *parent = nullptr);
    ~GmsslLib();

    // 加载 HEX 格式的公钥私钥
    int loadKey(const QByteArray &sk, const QByteArray &pk);

    // SM2 加密
    // 参数： 明文字符串
    // 返回值：HEX 格式密文，失败则返回空
    QByteArray sm2Encrypt(const QString &plaintext);

    // SM2 解密
    // 参数： HEX 格式密文
    // 返回值：解密后的字符串，失败则返回空
    QString sm2Decrypt(const QByteArray &ciphertext);

signals:
};

#endif // GMSSLLIB_H
