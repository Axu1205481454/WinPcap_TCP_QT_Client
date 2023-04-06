#include "MainWindow.h"
#include "getnics.h"

int flag = 0;

MainWindow::MainWindow(QWidget *parent)
    : QWidget(parent)
{
	initWidget();
	showAllNics();

	threadPool = new ThreadPool;

	// 点击连接按钮
	connect(btn_conn, &QPushButton::clicked, this, &MainWindow::connSlot);
	// 点击断开连接按钮
	connect(btn_disConn, &QPushButton::clicked, this, &MainWindow::disconnSlot);
	connect(this, &MainWindow::destroyed, this, &MainWindow::stopThreadWhenCloseSlot);

	// 发送消息按钮
	connect(btn_send, &QPushButton::clicked, this, &MainWindow::sendMsgSlot);


}


/* 界面布局 */
void MainWindow::initWidget()
{
	this->setWindowTitle(tr("Client"));
	this->resize(800, 800);
	this->setStyleSheet("background-color:#C0C0C0");

	lab_SRCIP = new QLabel(tr("SRCIP:"));
	lab_DSTIP = new QLabel(tr("DSTIP:"));
	lab_SRCPORT = new QLabel(tr("SRCPORT:"));
	lab_DSTPORT = new QLabel(tr("DSTPORT:"));
	lab_selectNic = new QLabel(tr("Nics:"));

	line_SRCIP = new QLineEdit(this);
	line_SRCIP->setText("192.168.199.1");
	line_DSTIP = new QLineEdit(this);
	line_DSTIP->setText("172.16.0.103");
	line_SRCPORT = new QLineEdit(this);
	line_SRCPORT->setText("8888");
	line_DSTPORT = new QLineEdit(this);
	line_DSTPORT->setText("8888");
	line_Send = new QLineEdit(this);

	box_selectNic = new QComboBox(this);
	//box_selectNic->resize(200, 10);

	btn_conn = new QPushButton(tr("conn"), this);
	btn_disConn = new QPushButton(tr("disconn"), this);
	btn_disConn->setEnabled(false);
	btn_send = new QPushButton(tr("send"), this);

	listWidget_info = new QListWidget(this);
	listWidget_info->setAlternatingRowColors(true);


	QHBoxLayout* hlayout_src = new QHBoxLayout();
	hlayout_src->addWidget(lab_SRCIP);
	hlayout_src->addWidget(line_SRCIP);
	hlayout_src->addStretch();
	hlayout_src->addWidget(lab_SRCPORT);
	hlayout_src->addWidget(line_SRCPORT);

	QHBoxLayout* hlayout_dst = new QHBoxLayout();
	hlayout_dst->addWidget(lab_DSTIP);
	hlayout_dst->addWidget(line_DSTIP);
	hlayout_dst->addStretch();
	hlayout_dst->addWidget(lab_DSTPORT);
	hlayout_dst->addWidget(line_DSTPORT);

	QHBoxLayout* hlayout_selectNic = new QHBoxLayout();
	hlayout_selectNic->addWidget(lab_selectNic);
	hlayout_selectNic->addWidget(box_selectNic);

	QHBoxLayout* hlayout_conn = new QHBoxLayout();
	hlayout_conn->addWidget(btn_conn);
	hlayout_conn->addStretch();
	hlayout_conn->addWidget(btn_disConn);

	QHBoxLayout* hlayout_listWidget = new QHBoxLayout();
	hlayout_listWidget->addWidget(listWidget_info);

	QHBoxLayout* hlayout_send = new QHBoxLayout();
	hlayout_send->addWidget(line_Send);
	hlayout_send->addWidget(btn_send);

	QVBoxLayout* vlayout_all = new QVBoxLayout(this);
	vlayout_all->addLayout(hlayout_src);
	vlayout_all->addLayout(hlayout_dst);
	vlayout_all->addLayout(hlayout_selectNic);
	vlayout_all->addLayout(hlayout_conn);
	vlayout_all->addLayout(hlayout_listWidget);
	vlayout_all->addLayout(hlayout_send);


}

/* 获取所有网卡 */
void MainWindow::showAllNics()
{
	pcap_if_t *alldevs = getAllNics();
	QStringList strList;

	// 遍历适配器
	for (auto i = alldevs; i != NULL; i = i->next)
	{
		QString str = "\\Device\\NPF_";
		int pos = QString::fromUtf8(i->name).indexOf(QRegExp("[{]+"));
		QString nic = QString::fromUtf8(i->name).mid(pos , -1);

		strList << str + nic;
	}
	
	// 显示到comboBox中
	box_selectNic->addItems(strList);
	
}

void MainWindow::packetSlot(QString info)
{
	listWidget_info->addItem(info);
}
void MainWindow::connStatusSlot(int connFlag)
{
	btn_conn->setEnabled(true);
	btn_disConn->setEnabled(false);
	line_SRCIP->setEnabled(true);
	line_SRCPORT->setEnabled(true);
	line_DSTIP->setEnabled(true);
	line_DSTPORT->setEnabled(true);
	box_selectNic->setEnabled(true);
}

void MainWindow::disconnSlot()
{
	btn_conn->setEnabled(true);
	btn_disConn->setEnabled(false);
	line_SRCIP->setEnabled(true);
	line_SRCPORT->setEnabled(true);
	line_DSTIP->setEnabled(true);
	line_DSTPORT->setEnabled(true);
	box_selectNic->setEnabled(true);
	
	subPacketHandle->flagFordisConn();

}

void MainWindow::stopThreadWhenCloseSlot()
{
	if (flag == 1) {
		subPacketHandle->quit();
		subPacketHandle->flagForCloseUI();
		subPacketHandle->wait();
	}

}

/* 发出点击连接按钮的信号 */
void MainWindow::connSlot()
{

	// 设置不可用防止篡改
	btn_conn->setEnabled(false);
	btn_disConn->setEnabled(true);
	line_SRCIP->setEnabled(false);
	line_SRCPORT->setEnabled(false);
	line_DSTIP->setEnabled(false);
	line_DSTPORT->setEnabled(false);
	box_selectNic->setEnabled(false);

	QString device = box_selectNic->currentText();
	int SRCPORT = (line_SRCPORT->text()).toInt();
	int DSTPORT = (line_DSTPORT->text()).toInt();
	QString SRCIP = line_SRCIP->text();
	QString DSTIP = line_DSTIP->text();

	flag = 1;
	//auto thread = threadPool->getFreeThread();
	subPacketHandle = new PacketHandle(device, SRCIP, DSTIP, SRCPORT, DSTPORT);
	connect(subPacketHandle, &PacketHandle::packetSignal, this, &MainWindow::packetSlot);
	connect(subPacketHandle, &PacketHandle::connStatusSignal, this, &MainWindow::connStatusSlot);
	connect(this, &MainWindow::sendMsg, subPacketHandle, &PacketHandle::getMsg);
	subPacketHandle->start();

}

void MainWindow::sendMsgSlot()
{
	qDebug() << "发送按钮被点击了。";
	QString msg = line_Send->text();
	emit sendMsg(msg);
}
