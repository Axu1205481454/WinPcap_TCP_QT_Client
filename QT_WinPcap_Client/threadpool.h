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


	QHash<QThread *, int> hashAllThread;			// 线程池线程合集，key为线程，value为对应线程工作量
	QHash<QThread *, int>::iterator m_CurThread;

};
