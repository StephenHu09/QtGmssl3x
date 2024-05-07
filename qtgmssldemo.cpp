#include "qtgmssldemo.h"
#include "ui_qtgmssldemo.h"

#include <QFile>
#include <QDebug>

QtGmsslDemo::QtGmsslDemo(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::QtGmsslDemo)
{
    ui->setupUi(this);

    initView();
    initData();


    gmsslTest();
}

QtGmsslDemo::~QtGmsslDemo()
{
    delete ui;
}

void QtGmsslDemo::initView()
{
    this->resize(1440, 900);
}

void QtGmsslDemo::initData()
{
    loadSM2Key();
}

void QtGmsslDemo::gmsslTest()
{
    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    size_t len;

    const char* str = "cdxj@123456";
    QByteArray ba(str, strlen(str));

    sm2_encrypt(&m_pub_key, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), ciphertext, &len);

    QString hexString;
    for (int i = 0; i < len; ++i) {
        hexString.append(QString("%1").arg(ciphertext[i], 2, 16, QChar('0')));
    }

    // QString str = QString(QLatin1String(reinterpret_cast<const  char*>(ciphertext)));
    qDebug() << "ciphertext len:" << len;
    qDebug() << "ciphertext asn1 :" << hexString;

    SM2_CIPHERTEXT ctxt;
    sm2_do_encrypt(&m_sm2_key, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), &ctxt);

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

    sm2_decrypt(&m_sm2_key, ciphertext, len, plaintext, &len);
    plaintext[len] = 0;
    qDebug() << "plaintext: " << QString(QLatin1String(reinterpret_cast<const  char*>(plaintext)));

    gmssl_secure_clear(&m_sm2_key, sizeof(m_sm2_key));
    gmssl_secure_clear(&m_pub_key, sizeof(m_pub_key));

}

void QtGmsslDemo::on_btnEncryption_clicked(bool checked)
{

}


void QtGmsslDemo::on_btnDecryption_clicked(bool checked)
{

}


void QtGmsslDemo::on_textPlain_textChanged(const QString &arg1)
{

}


void QtGmsslDemo::on_decStr_textChanged(const QString &arg1)
{

}


void QtGmsslDemo::on_comboBoxEncryType_currentIndexChanged(int index)
{

}


void QtGmsslDemo::on_comboBoxType_currentIndexChanged(int index)
{

}

void QtGmsslDemo::loadSM2Key()
{
    /* pem 密钥文件，可以通过 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 网站将 HEX 密钥数据转化成pem格式，再保存为文件即可 */

    // 代码处理 TODO:
    // 如何将 HEX 十六进制字符串格式的公钥和私钥转成pem格式的base64内容：
    // 首先用 include/gmssl/hex.h 中的 hex_to_bytes 将公钥或者私钥转换成字节序列
    // 然后用 sm2_key_set_public_key 或 sm2_key_set_private_key 将其转化为 SM2_KEY 类型
    // 然后用 sm2_public_key_info_to_pem 或 sm2_private_key_info_encrypt_to_pem 将 SM2_KEY 写入PEM文件

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

    if (sm2_private_key_from_pem(&m_sm2_key, keyfp) != 1) {
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

    if (sm2_public_key_info_from_pem(&m_pub_key, pubkeyfp) != 1) {
        qDebug() << "load public key failure";
        return;
    }

    qDebug() << "load public key success : " << pubkeyfile;

    if (keyfp) {
        fclose(keyfp);
        keyfp = nullptr;
    }

    if (pubkeyfp) {
        fclose(pubkeyfp);
        pubkeyfp = nullptr;
    }

}

