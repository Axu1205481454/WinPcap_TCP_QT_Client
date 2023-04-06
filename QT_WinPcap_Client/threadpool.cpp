#include "threadpool.h"

ThreadPool::ThreadPool(const int maxThread)
{
	QThread *pThread;
	// 初始化线程池
	for (int i = 0; i < maxThread; ++i) {
		pThread = new QThread;
		hashAllThread.insert(pThread, 0);
		pThread->start();
	}
}

ThreadPool::~ThreadPool()
{
	QThread *pThread;
	for (auto it = hashAllThread.begin(); it != hashAllThread.end(); ++it)
	{
		pThread = it.key();
		pThread->exit();
		pThread->wait(1000);
		delete pThread;
	}
}

QThread* ThreadPool::getFreeThread()
{
	QThread *pThread = nullptr;

	// auto：迭代器类型
	auto begin = hashAllThread.begin();
	for (begin; begin != hashAllThread.end(); ++begin)
	{
		if (begin.value() < MAX_VALUE)
		{
			m_CurThread = begin;
			m_CurThread.value()++;
			pThread = m_CurThread.key();
			break;
		}
	}


	return pThread;
}


void ThreadPool::setThreadFree(QThread *pThread)
{
	auto temp = hashAllThread.find(pThread);
	temp.value()--;
}