#include "qtgmssldemo.h"
#include "ui_qtgmssldemo.h"

#include <QFile>
#include <QDebug>

#include "gmssl/sm2.h"
#include "gmssl/mem.h"

QtGmsslDemo::QtGmsslDemo(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::QtGmsslDemo)
{
    ui->setupUi(this);

    gmsslTest();
}

QtGmsslDemo::~QtGmsslDemo()
{
    delete ui;
}

void QtGmsslDemo::gmsslTest()
{
    SM2_KEY sm2_key;
    SM2_KEY pub_key;

    QString keyfile = "sm2.pem";
    QFile file(keyfile);
    if (!file.exists()) {
        qDebug() << "File does not exist:" << keyfile;
        return;
    }

    FILE *keyfp = fopen(keyfile.toStdString().c_str(), "rb"); // "r" 表示只读，可以根据需要更改
    if (!keyfp) {
        qDebug() << "Failed to open file:" << keyfile;
        return; // 或者处理错误
    }

    if (sm2_private_key_from_pem(&sm2_key, keyfp) != 1) {
        qDebug() << "load key failure";
        return;
    }

    qDebug() << "load private key success : " << keyfile;


    QString pubkeyfile = "sm2pub.pem";
    QFile pubfile(pubkeyfile);
    if (!pubfile.exists()) {
        qDebug() << "File does not exist:" << pubkeyfile;
        return;
    }

    FILE *pubkeyfp = fopen(pubkeyfile.toStdString().c_str(), "rb"); // "r" 表示只读，可以根据需要更改
    if (!pubkeyfp) {
        qDebug() << "Failed to open pubkeyfile :" << pubkeyfile;
        return; // 或者处理错误
    }

    if (sm2_public_key_info_from_pem(&pub_key, pubkeyfp) != 1) {
        qDebug() << "load public key failure";
        return;
    }

    qDebug() << "load public key success : " << pubkeyfile;


    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    size_t len;

    const char* str = "12345678";
    QByteArray ba(str, strlen(str));

    sm2_encrypt(&pub_key, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), ciphertext, &len);

    QString hexString;
    for (int i = 0; i < len; ++i) {
        hexString.append(QString("%1").arg(ciphertext[i], 2, 16, QChar('0')));
    }

    // QString str = QString(QLatin1String(reinterpret_cast<const  char*>(ciphertext)));
    qDebug() << "ciphertext len:" << len;
    qDebug() << "ciphertext asn1 :" << hexString;

    SM2_CIPHERTEXT ctxt;
    sm2_do_encrypt(&sm2_key, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), &ctxt);

    QByteArray c1c3c2;
    c1c3c2.append(static_cast<char>(0x04)); // 添加 0x04开头
    QByteArray x(reinterpret_cast<const char*>(ctxt.point.x), 32);  // SM2_POINT.x[32];
    QByteArray y(reinterpret_cast<const char*>(ctxt.point.y), 32);  // SM2_POINT.y[32];
    QByteArray hash(reinterpret_cast<const char*>(ctxt.hash), 32);  // SM2_CIPHERTEXT.hash[32]
    QByteArray cipherText1(reinterpret_cast<const char*>(ctxt.ciphertext), ctxt.ciphertext_size);

    c1c3c2.append(x);
    c1c3c2.append(y);
    c1c3c2.append(hash);
    c1c3c2.append(cipherText1);
    QString hexStr2 = QString::fromUtf8(c1c3c2.toHex());
    qDebug() << "ciphertext c1c3c2 :" << hexStr2;

    sm2_decrypt(&sm2_key, ciphertext, len, plaintext, &len);
    plaintext[len] = 0;
    qDebug() << "plaintext: " << QString(QLatin1String(reinterpret_cast<const  char*>(plaintext)));

    gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
    gmssl_secure_clear(&pub_key, sizeof(pub_key));

    if (keyfp) {
        fclose(keyfp);
        keyfp = nullptr;
    }

    if (pubkeyfp) {
        fclose(pubkeyfp);
        pubkeyfp = nullptr;
    }
}
