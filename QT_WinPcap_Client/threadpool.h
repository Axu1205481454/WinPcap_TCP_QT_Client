#pragma once
#include <QHash>
#include <QThread>

#define MAX_THREAD 50
#define MAX_VALUE 1

class ThreadPool
{
public:
	explicit ThreadPool(const int maxThread = MAX_THREAD);
	~ThreadPool();

	QThread *getFreeThread();

	void setThreadFree(QThread *pThread);

private:


	QHash<QThread *, int> hashAllThread;			// �̳߳��̺߳ϼ���keyΪ�̣߳�valueΪ��Ӧ�̹߳�����
	QHash<QThread *, int>::iterator m_CurThread;

};
