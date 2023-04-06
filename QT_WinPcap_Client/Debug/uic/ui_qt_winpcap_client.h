/********************************************************************************
** Form generated from reading UI file 'qt_winpcap_client.ui'
**
** Created by: Qt User Interface Compiler version 5.12.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_QT_WINPCAP_CLIENT_H
#define UI_QT_WINPCAP_CLIENT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_QT_WinPcap_ClientClass
{
public:

    void setupUi(QWidget *QT_WinPcap_ClientClass)
    {
        if (QT_WinPcap_ClientClass->objectName().isEmpty())
            QT_WinPcap_ClientClass->setObjectName(QString::fromUtf8("QT_WinPcap_ClientClass"));
        QT_WinPcap_ClientClass->resize(600, 400);

        retranslateUi(QT_WinPcap_ClientClass);

        QMetaObject::connectSlotsByName(QT_WinPcap_ClientClass);
    } // setupUi

    void retranslateUi(QWidget *QT_WinPcap_ClientClass)
    {
        QT_WinPcap_ClientClass->setWindowTitle(QApplication::translate("QT_WinPcap_ClientClass", "QT_WinPcap_Client", nullptr));
    } // retranslateUi

};

namespace Ui {
    class QT_WinPcap_ClientClass: public Ui_QT_WinPcap_ClientClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_QT_WINPCAP_CLIENT_H
