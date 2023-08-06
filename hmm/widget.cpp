#include "widget.h"
#include "ui_widget.h"
#include<QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->pb_coffee->setEnabled(false);
    ui->pb_tea->setEnabled(false);
    ui->pb_milk->setEnabled(false);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::change_money(int diff){
    money+=diff;
    ui->lcdNumber->display(money);
}

void Widget::check_bnt(){
    if(money >= 100){
        ui->pb_coffee->setEnabled(true);
    }
    if(money >= 150){
        ui->pb_tea->setEnabled(true);
    }
    if(money >= 200){
        ui->pb_milk->setEnabled(true);
    }

}

void Widget::check_bnt_out(){
    if(money < 100){
        ui->pb_coffee->setEnabled(false);
    }
    if(money < 150){
        ui->pb_tea->setEnabled(false);
    }
    if(money < 200){
        ui->pb_milk->setEnabled(false);
    }
}


void Widget::on_pb_10_clicked()
{
    change_money(10);
    check_bnt();
}


void Widget::on_pb_50_clicked()
{
    change_money(50);
    check_bnt();
}


void Widget::on_pb_100_clicked()
{
    change_money(100);
    check_bnt();
}


void Widget::on_pb_500_clicked()
{
    change_money(500);
    check_bnt();
}


void Widget::on_pb_coffee_clicked()
{
    change_money(-100);
    check_bnt_out();
}


void Widget::on_pb_tea_clicked()
{
    change_money(-150);
    check_bnt_out();
}

void Widget::on_pb_milk_clicked()
{
    change_money(-200);
    check_bnt_out();
}


void Widget::on_pb_reset_clicked()
{
    QMessageBox mb;
    fi_hun = money / 500;
    money = money % 500;
    hun = money / 100;
    money = money % 100;
    fi_ty = money / 50;
    money = money % 50;
    ten = money / 10;

    money = 0;
    change_money(0);
    check_bnt_out();
    QString message = "500: " + QString::number(fi_hun) +
                      "\n100: " + QString::number(hun) +
                      "\n50: " + QString::number(fi_ty) +
                      "\n10: " + QString::number(ten);

    mb.information(nullptr, "Alert", message);
}



