#ifndef QTGMSSLDEMO_H
#define QTGMSSLDEMO_H

#include <QMainWindow>

#include "gmssllib.h"

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

private:
    void initView();
    void initData();
    void gmsslTest();

private slots:
    void on_btnEncryption_clicked(bool checked);

    void on_btnDecryption_clicked(bool checked);

    void on_textPlain_textChanged(const QString &arg1);

    void on_comboBoxEncryType_currentIndexChanged(int index);

    void on_comboBoxType_currentIndexChanged(int index);

    void on_btnPriSave_clicked(bool checked);

    void on_btnPubSave_clicked(bool checked);

    void on_textCipherStr_textChanged();

    void on_btnDecClear_clicked();

private:
    Ui::QtGmsslDemo *ui;
    // GmsslLib *gmsslObj;

    SM2_KEY m_sm2PriKey;
    SM2_KEY m_sm2PubKey;
};
#endif // QTGMSSLDEMO_H
