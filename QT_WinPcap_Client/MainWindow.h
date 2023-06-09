#pragma once
#if _MSC_VER >= 1600
#pragma execution_character_set("utf-8")// 该指令仅支持VS环境
#endif
#include <QtWidgets/QWidget>
#include <QLabel>
#include <QPushButton>
#include <QLayout>
#include <QLineEdit>
#include <QListWidget>
#include <QComboBox>
#include <QString>
#include <QStringList>
#include <process.h>
#include <QRunnable>
#include <QThread>
#include <QThreadPool>
#include "packetHandle.h"
#include "threadpool.h"

class MainWindow : public QWidget
{
    Q_OBJECT

public:
	MainWindow(QWidget *parent = nullptr);

	PacketHandle* subPacketHandle;
signals:
	void sendMsg(QString msg);


private:
	ThreadPool* threadPool;

private:
	QLabel* lab_SRCIP;
	QLabel* lab_DSTIP;
	QLabel* lab_SRCPORT;
	QLabel* lab_DSTPORT;
	QLabel* lab_selectNic;

	QLineEdit* line_SRCIP;
	QLineEdit* line_DSTIP;
	QLineEdit* line_SRCPORT;
	QLineEdit* line_DSTPORT;
	QLineEdit* line_Send;

	QComboBox* box_selectNic;

	QPushButton* btn_conn;
	QPushButton* btn_disConn;
	QPushButton* btn_send;

	QListWidget* listWidget_info;
	
	void initWidget();
	void showAllNics();

private slots:
	void connSlot();
	void packetSlot(QString info);
	void disconnSlot();
	void stopThreadWhenCloseSlot();
	void connStatusSlot(int connFlag);
	void sendMsgSlot();
};
