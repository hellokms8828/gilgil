#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();
    int money {0}; //equeal enables... but {0} init better..
    int fi_hun {0};
    int hun {0};
    int fi_ty {0};
    int ten {0};
    void change_money(int diff);
    void check_bnt();
    void check_bnt_out();

private slots:
    void on_pb_10_clicked();

    void on_pb_50_clicked();

    void on_pb_100_clicked();


    void on_pb_500_clicked();


    void on_pb_coffee_clicked();

    void on_pb_tea_clicked();

    void on_pb_milk_clicked();

    void on_pb_reset_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
