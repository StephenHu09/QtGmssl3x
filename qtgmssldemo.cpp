#include "qtgmssldemo.h"
#include "ui_qtgmssldemo.h"

#include <QFile>
#include <QDebug>

// 密钥生成工具 https://const.net.cn/tool/sm2/genkey/
// 默认长度 64，代表32个字节
static const char *PRIVATE_KEY = "520239279C961A507D5B219E7179AF7067B5BE908480A8651F2801DFF4998B0A";
// 默认长度128，代表64个字节，忽略掉开头的 04
static const char *PUBLIC_KEY = "8B9B618F42EE8949B97A4806D7575CAD0873D9F11E976902AF1BFCC95CB9C0EDFA4948138E5561CA5D02B42AD5F18873DDF1FBB07515F8B5E364331A3D16241F";

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

    // 设置样式表
    QString style1 = "QGroupBox{background-color: #c7e0f4;}";
    ui->groupBox1->setStyleSheet(style1);

    QString style2 = "QGroupBox{background-color: #f7eead;}";
    ui->groupBox2->setStyleSheet(style2);
    ui->WidgetEnc->setStyleSheet("QWidget#WidgetEnc{background-color: #f7eead;}");

    QString style3 = "QGroupBox{background-color: #d3f9d8;}";
    ui->groupBox3->setStyleSheet(style3);
}

void QtGmsslDemo::initData()
{
    QString priKey(PRIVATE_KEY);
    QString pubKey(PUBLIC_KEY);
    ui->lineEditSK->setText(priKey);
    ui->lineEditPK->setText(pubKey);
}

void QtGmsslDemo::gmsslTest()
{
    GmsslLib *gmsslObj = new GmsslLib(this);
    gmsslObj->loadKeyFormHex(PRIVATE_KEY, PUBLIC_KEY);

    // 字符串 加解密 ASN.1格式
    QString str = "123456ASN1";
    QString cipherStr = gmsslObj->sm2EncryptASN1(str);
    qDebug() << "cipherStr ASN.1 :" << cipherStr; // 30 开头的密文
    QString plainStr = gmsslObj->sm2DecryptASN1(cipherStr);
    qDebug() << "ASN.1 解密结果 ：" <<  plainStr;

    // 字符串 加解密 旧格式hex
    QString str2 = "123456HEX";
    QString cipherStr2 = gmsslObj->sm2EncryptHex(str2);
    qDebug() << "cipherStr2 HEX :" << cipherStr2;
    QString plainStr2 = gmsslObj->sm2DecryptHex(cipherStr2);
    qDebug() << "HEX 解密结果 ：" <<  plainStr2;
}


void QtGmsslDemo::on_btnEncryption_clicked(bool checked)
{
    QString plainStr = ui->textPlain->text();
    if (plainStr.isEmpty()) {
        return;
    }

    // 公钥加密
    QString pubKeyStr = ui->lineEditPK->text();
    if (pubKeyStr.isEmpty()) {
        qDebug() << "public key str is empty";
        return;
    }
    if (pubKeyStr.startsWith("04")) {
        pubKeyStr.remove(0, 2);
    }
    if (pubKeyStr.size() != 128) {
        qDebug() << "public key str len is error";
        return;
    }

    GmsslLib *gmsslObj = new GmsslLib(this);

    if (gmsslObj->loadPublicKey(pubKeyStr) != 0) {
        qDebug() << "public key load failed";
        delete gmsslObj;
        return;
    }


    QString cipherHexAsn1 = gmsslObj->sm2EncryptASN1(plainStr);
    ui->textCipherDer->clear();
    ui->textCipherDer->insertPlainText(cipherHexAsn1);

    // 旧格式密文: 04开头密文，常用于后端， 去掉04开头的密文，常用于前端
    QString cipherHex = gmsslObj->sm2EncryptHex(plainStr);
    ui->textCipherFront->clear();
    ui->textCipherFront->insertPlainText(cipherHex);
    ui->textCipherBack->clear();
    ui->textCipherBack->insertPlainText(cipherHex.prepend("04"));

    delete gmsslObj;
}

void QtGmsslDemo::on_btnDecryption_clicked(bool checked)
{
    ui->decStr->clear();

    QString cipherStr = ui->textCipherStr->toPlainText();
    if (cipherStr.isEmpty()) {
        return;
    }

    cipherStr.replace(QRegExp("[^0-9A-Fa-f]"), ""); // 移除非Hex数据

    // 私钥解密
    QString priKeyStr = ui->lineEditSK->text();
    if (priKeyStr.isEmpty() || priKeyStr.size() != 64) {
        qDebug() << "private key str is error";
        return;
    }

    GmsslLib *gmsslObj = new GmsslLib(this);
    if (gmsslObj->loadPrivateKey(priKeyStr) != 0) {
        qDebug() << "private key load failed";
        delete gmsslObj;
        return;
    }

    QString plainStr;
    if (ui->comboBoxEncryType->currentIndex() == 0) {
        plainStr = gmsslObj->sm2DecryptASN1(cipherStr);
        ui->decStr->setText(plainStr);
    } else {
        plainStr = gmsslObj->sm2DecryptHex(cipherStr);
        ui->decStr->setText(plainStr);
    }

    if (!plainStr.isEmpty()) {
        qDebug() << "解密成功 Plain Text =" << plainStr;
    }

    delete gmsslObj;
}

void QtGmsslDemo::on_textPlain_textChanged(const QString &arg1)
{
    ui->textCipherDer->clear();
    ui->textCipherFront->clear();
    ui->textCipherBack->clear();
}

void QtGmsslDemo::on_comboBoxEncryType_currentIndexChanged(int index)
{

}

void QtGmsslDemo::on_comboBoxType_currentIndexChanged(int index)
{

}

void QtGmsslDemo::on_btnPriSave_clicked(bool checked)
{
    QString priKeyStr = ui->lineEditSK->text();

    if (priKeyStr.isEmpty() || priKeyStr.size() != 64) {
        qDebug() << "private key str is error";
        return;
    }

    GmsslLib *gmsslObj = new GmsslLib(this);

    if (gmsslObj->loadPrivateKey(priKeyStr) != 0) {
        qDebug() << "private key load failed";
        delete gmsslObj;
        return;
    }

    if (gmsslObj->savePrivateKeyToPem("test_pri.pem") != 0) {
        qDebug() << "private key save pem failed";
        delete gmsslObj;
        return;
    }

    qDebug() << "private key save pem success";
    delete gmsslObj;

}

void QtGmsslDemo::on_btnPubSave_clicked(bool checked)
{
    QString pubKeyStr = ui->lineEditPK->text();

    if (pubKeyStr.isEmpty()) {
        qDebug() << "public key str is empty";
        return;
    }
    // 去掉 04 头
    if (pubKeyStr.startsWith("04")) {
        pubKeyStr.remove(0, 2);
    }
    if (pubKeyStr.size() != 128) {
        qDebug() << "public key str len is error";
        return;
    }

    GmsslLib *gmsslObj = new GmsslLib(this);

    if (gmsslObj->loadPublicKey(pubKeyStr) != 0) {
        qDebug() << "public key load failed";
        delete gmsslObj;
        return;
    }

    if (gmsslObj->savePublicKeyToPem("test_pub.pem") != 0) {
        qDebug() << "public key save pem failed";
        delete gmsslObj;
        return;
    }

    qDebug() << "public key save pem success";
    delete gmsslObj;
}


void QtGmsslDemo::on_textCipherStr_textChanged()
{
    ui->decStr->clear();

    QString str = ui->textCipherStr->toPlainText();
    if (str.isEmpty() || str.size() < 2) {
        return;
    }

    if (str.startsWith("30")) {
        ui->comboBoxEncryType->setCurrentIndex(0);
    } else {
        ui->comboBoxEncryType->setCurrentIndex(1);
    }
}

void QtGmsslDemo::on_btnDecClear_clicked()
{
    ui->decStr->clear();
}

