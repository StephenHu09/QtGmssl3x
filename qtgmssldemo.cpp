#include "qtgmssldemo.h"
#include "ui_qtgmssldemo.h"

#include <QFile>
#include <QDebug>

#include "gmssl/hex.h"

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

    sm2_encrypt(&m_sm2PubKey, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), ciphertext, &len);

    QString hexString;
    for (int i = 0; i < len; ++i) {
        hexString.append(QString("%1").arg(ciphertext[i], 2, 16, QChar('0')));
    }

    // QString str = QString(QLatin1String(reinterpret_cast<const  char*>(ciphertext)));
    qDebug() << "ciphertext len:" << len;
    qDebug() << "ciphertext asn1 :" << hexString;

    SM2_CIPHERTEXT ctxt;
    sm2_do_encrypt(&m_sm2PriKey, reinterpret_cast<uint8_t *>(ba.data()), ba.size(), &ctxt);

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

    sm2_decrypt(&m_sm2PriKey, ciphertext, len, plaintext, &len);
    plaintext[len] = 0;
    qDebug() << "plaintext: " << QString(QLatin1String(reinterpret_cast<const  char*>(plaintext)));

    gmssl_secure_clear(&m_sm2PriKey, sizeof(m_sm2PriKey));
    gmssl_secure_clear(&m_sm2PubKey, sizeof(m_sm2PubKey));

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
    // 下面两种方式二选一
    loadKeyFormHex();

    // loadKeyFormPem();
}

void QtGmsslDemo::loadKeyFormPem()
{
    /* pem 密钥文件，可以先通过内部接口 savePrivateKeyToPem 和 savePublicKeyToPem 生成，
     * 也可以通过 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 网站将 HEX 密钥数据转化成pem格式，
     * 再保存为文件即可，不过两种方式的私钥pem文件格式有差异，对应加载解析接口不同，需要注意 */

    QString keyfile = "sm2_prikey.pem";
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

    /*
     * 注： 使用网站 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 生成的 pem 文件格式数据，
     * 是 -----BEGIN EC PRIVATE KEY----- 格式的数据，
     * 需要使用 sm2_private_key_from_pem 接口进行加载才能正确解析
     */

    if (sm2_private_key_info_from_pem(&m_sm2PriKey, keyfp) != 1) {
        qDebug() << "load key failure";
        return;
    }

    qDebug() << "load private key success : " << keyfile;


    QString pubkeyfile = "sm2_pubkey.pem";
    QFile pubfile(pubkeyfile);
    if (!pubfile.exists()) {
        qDebug() << "File does not exist:" << pubkeyfile;
        return;
    }

    FILE *pubkeyfp = fopen(pubkeyfile.toStdString().c_str(), "rb"); // "r" 表示只读，可以根据需要更改
    if (!pubkeyfp) {
        qDebug() << "Failed to open pubkeyfile :" << pubkeyfile;
        return;
    }

    if (sm2_public_key_info_from_pem(&m_sm2PubKey, pubkeyfp) != 1) {
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

void QtGmsslDemo::loadKeyFormHex()
{
    // 代码处理 :
    // 如何将 HEX 十六进制字符串格式的公钥和私钥转成pem格式的base64内容：
    // 1. 首先用 include/gmssl/hex.h 中的 hex_to_bytes 将公钥或者私钥转换成字节序列
    // 2. 然后用 sm2_key_set_public_key 或 sm2_key_set_private_key 将其转化为 SM2_KEY 类型
    // 3. 然后用 sm2_public_key_info_to_pem 或 sm2_private_key_info_encrypt_to_pem 将 SM2_KEY 写入PEM文件

    // 默认长度 64，代表32个字节
    const char *privateKey = "3037723d47292171677ec8bd7dc9af696c7472bc5f251b2cec07e65fdef22e25";

    // 默认长度128，代表64个字节，忽略掉开头的 04
    const char *publicKey = "298364ec840088475eae92a591e01284d1abefcda348b47eb324bb521bb03b0b2a5bc393f6b71dabb8f15c99a0050818b56b23f31743b93df9cf8948f15ddb54";


    uint8_t priBytes[32];
    size_t priLen;
    hex_to_bytes(privateKey, 64, priBytes, &priLen);

    sm2_z256_t private_key;
    sm2_z256_from_bytes(private_key, priBytes);
    if (sm2_key_set_private_key(&m_sm2PriKey, private_key) != 1) {
        gmssl_secure_clear(private_key, 32);
        qDebug() << "HEX set private key failed";
        return;
    }
    gmssl_secure_clear(private_key, 32);
    qDebug() << "HEX set private key success";

    savePrivateKeyToPem(&m_sm2PriKey, "sm2_prikey.pem");


    uint8_t pubBytes[64];
    size_t pubLen;
    hex_to_bytes(publicKey, 128, pubBytes, &pubLen);

    SM2_Z256_POINT point;
    if (sm2_z256_point_from_bytes(&point, pubBytes) != 1) {
        qDebug() << "HEX set public key point failed";
        return;
    }

    if (sm2_key_set_public_key(&m_sm2PubKey, &point) != 1) {
        qDebug() << "HEX set public key failed";
        return;
    }
    qDebug() << "HEX set public key success";

    savePublicKeyToPem(&m_sm2PubKey, "sm2_pubkey.pem");

}

void QtGmsslDemo::savePrivateKeyToPem(SM2_KEY *priKey, const QString &path)
{
    if (path.isEmpty()) {
        return;
    }


    QString priKeyfile = path;
    QFile file(priKeyfile);
    FILE *prifp = fopen(priKeyfile.toStdString().c_str(), "w");
    if (!prifp) {
        qDebug() << "Failed to open file:" << priKeyfile;
        return; // 或者处理错误
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
        return;
    }

    qDebug() << "save private key pem success";

    fclose(prifp);
    prifp = nullptr;
}

void QtGmsslDemo::savePublicKeyToPem(SM2_KEY *pubKey, const QString &path)
{
    if (path.isEmpty()) {
        return;
    }

    QString pubKeyfile = path;
    QFile file(pubKeyfile);
    FILE *pubfp = fopen(pubKeyfile.toStdString().c_str(), "w");
    if (!pubfp) {
        qDebug() << "Failed to open file:" << pubKeyfile;
        return;
    }

    if (sm2_public_key_info_to_pem(&m_sm2PubKey, pubfp) != 1) {
        qDebug() << "save private key pem failure";
        fclose(pubfp);
        pubfp = nullptr;
        return;
    }

    qDebug() << "save private key pem success";

    fclose(pubfp);
    pubfp = nullptr;
}

