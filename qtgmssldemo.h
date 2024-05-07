#ifndef QTGMSSLDEMO_H
#define QTGMSSLDEMO_H

#include <QMainWindow>

#include "gmssl/sm2.h"
#include "gmssl/mem.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class QtGmsslDemo;
}
QT_END_NAMESPACE

class QtGmsslDemo : public QMainWindow
{
    Q_OBJECT

public:
    QtGmsslDemo(QWidget *parent = nullptr);
    ~QtGmsslDemo();

    void initView();
    void initData();

private slots:
    void on_btnEncryption_clicked(bool checked);

    void on_btnDecryption_clicked(bool checked);

    void on_textPlain_textChanged(const QString &arg1);

    void on_decStr_textChanged(const QString &arg1);

    void on_comboBoxEncryType_currentIndexChanged(int index);

    void on_comboBoxType_currentIndexChanged(int index);

private:
    void loadSM2Key();

    void gmsslTest();


private:
    Ui::QtGmsslDemo *ui;

    SM2_KEY m_sm2_key;
    SM2_KEY m_pub_key;
};
#endif // QTGMSSLDEMO_H
