#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_Server.h"

class Server : public QMainWindow
{
    Q_OBJECT

public:
    Server(QWidget *parent = nullptr);
    ~Server();

private:
    Ui::ServerClass ui;
};
