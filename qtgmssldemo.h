#ifndef QTGMSSLDEMO_H
#define QTGMSSLDEMO_H

#include <QMainWindow>

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
    void gmsslTest();

private:
    Ui::QtGmsslDemo *ui;
};
#endif // QTGMSSLDEMO_H
