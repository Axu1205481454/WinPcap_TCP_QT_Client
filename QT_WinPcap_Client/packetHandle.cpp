#include "packetHandle.h"
pcap_t* adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned int netmask;
struct bpf_program fcode;
char* filter;
bool isShouldReply;
bool btnDisconnReply;
int step;
unsigned int next_seq = 0x42345678;
unsigned int next_ack_seq = 0;

QString my_msg = "ERROR!";

bool disconnFlag = false;
int connOK = 1;
QString temp_device;
QString temp_SRCIP;
QString temp_DSTIP;
char* m_device;
char* m_SRCIP;
char* m_DSTIP;
int m_SRCPORT;
int m_DSTPORT;

int isRST = 0;
int fin_count = 1;// 记录主动断开收到了几次回复
PacketHandle* PacketHandle::myPacketHandle = nullptr;

PacketHandle::PacketHandle(QString device, QString SRCIP, QString DSTIP, int SRCPORT, int DSTPORT,QObject *parent)
{
	myPacketHandle = this;
	connect(this, &PacketHandle::packetStaticSignal, this, &PacketHandle::packetStaticSlot);
	connect(this, &PacketHandle::connStatusStaticSignal, this, &PacketHandle::connStatusStaticSlot);

	temp_device = device;
	temp_SRCIP = SRCIP;
	temp_DSTIP = DSTIP;
	m_SRCPORT = SRCPORT;
	m_DSTPORT = DSTPORT;

	adhandle = NULL;
	netmask = 0xffffff;
	//filter = (char *)"tcp";
	filter = (char *)"tcp port 8888";
	isShouldReply = false;
	btnDisconnReply = false;
	step = 0;
}

void PacketHandle::run()
{
	// SRCIP
	QByteArray ba = (temp_SRCIP).toLatin1();
	m_SRCIP = ba.data();
	// DSTIP
	QByteArray ba1 = (temp_DSTIP).toLatin1();
	m_DSTIP = ba1.data();
	// Nic
	QByteArray ba2 = (temp_device).toLatin1();
	m_device = ba2.data();
	// 返回pcap_t*类型指针
	if ((adhandle = pcap_open(m_device, 0x10000, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		qDebug() << "[pcap_open error] :";
		QString info = "[pcap_open error]";
		emit myPacketHandle->packetStaticSignal(info);
		qDebug() << errbuf;
		return;
	}
	if (pcap_compile(adhandle, &fcode, filter, 1, netmask) == -1)
	{
		qDebug() << pcap_geterr(adhandle);
		return;
	}
	if (pcap_setfilter(adhandle, &fcode) == -1)
	{
		qDebug() << pcap_geterr(adhandle);
		return;
	}

	unsigned long p = _beginthread(send_packet_handle, 0, NULL);

	pcap_loop(adhandle, 0, my_pcap_handler, NULL);
}

void PacketHandle::flagForCloseUI()
{
	pcap_breakloop(adhandle);
}

void PacketHandle::flagFordisConn()
{
	disconnFlag = true;
	btnDisconnReply = true;
}

void PacketHandle::send_packet_handle(void * arg)
{
	//三次握手不含数据  
	char tcp_buffer[566] = { 0 };  //14 以太网头部, 20 ip头, 20+512 tcp头, 没有其它数据  

	ether_header* pether_header = (ether_header*)tcp_buffer;
	ip_header* pip_header = (ip_header*)(tcp_buffer + sizeof(ether_header));
	tcp_header* ptcp_header = (tcp_header*)(tcp_buffer + sizeof(ether_header) + sizeof(ip_header));


	//设置以太网头部  
	//所有MAC位置1  
	unsigned char mac[] = { 80,194,232,170,161,207 };
	memcpy(pether_header, mac, 6);
	//memset(pether_header, 1, 12);
	pether_header->ether_type = htons(ETHERTYPE_IP);

	//设置IP头  
	pip_header->ihl = sizeof(ip_header) / 4;
	pip_header->version = 4;
	pip_header->tos = 0;
	pip_header->tot_len = htons(sizeof(tcp_buffer) - sizeof(ether_header)); //12288  
	pip_header->id = 616;                                         //616  
	pip_header->frag_off = 64;
	pip_header->ttl = 128;
	pip_header->protocol = IPPROTO_TCP;
	pip_header->check = 0;
	pip_header->saddr = inet_addr(m_SRCIP);
	pip_header->daddr = inet_addr(m_DSTIP);
	pip_header->check = in_cksum((u_int16_t*)pip_header, sizeof(ip_header));

	//设置TCP头  
	ptcp_header->source = htons(m_SRCPORT);
	ptcp_header->dest = htons(m_DSTPORT);
	ptcp_header->seq = htonl((unsigned int)0x42345678);
	ptcp_header->ack_seq = htonl((unsigned int)0);
	ptcp_header->doff = sizeof(tcp_header) / 4;
	ptcp_header->res1 = 0;
	ptcp_header->res2 = 0;
	ptcp_header->fin = 0;
	ptcp_header->syn = 1;
	ptcp_header->rst = 0;
	ptcp_header->psh = 0;
	ptcp_header->ack = 0;
	ptcp_header->urg = 0;
	ptcp_header->window = 65535;
	ptcp_header->check = 0;
	ptcp_header->urg_ptr = 0;

	// 数据部分(测试)
	u_char data[512];
	memset(data, 0, sizeof(data));
	memcpy(ptcp_header->data, data, 512);

	ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));

	//发送一个SYN包到对方  
	if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
	{
		qDebug() << "发送SYN包失败！";
		return;
	}

	QString info = "握手连接[1]:(Client:" + QString::fromUtf8(uint_to_addr(pip_header->saddr)) + ")--->(Server:" + QString::fromUtf8(uint_to_addr(pip_header->daddr)) + ")";
	emit myPacketHandle->packetStaticSignal(info);

	while (true)
	{
		if (isShouldReply) {
			break;
		}
		else
		{
			while (isRST == 1 && disconnFlag==false) {
				//发送一个SYN包到对方  
				if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
				{
					return;
				}
				emit myPacketHandle->packetStaticSignal("连接失败,重连中....");
				Sleep(1000);
			}
		}

		Sleep(100);
	}

	//发送一个ACK包到对方  
	ptcp_header->syn = 0;
	ptcp_header->ack = 1;
	ptcp_header->seq = htonl(next_seq);
	ptcp_header->ack_seq = htonl(next_ack_seq);
	ptcp_header->check = 0;
	ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));

	isShouldReply = false;
	step = 1;
	if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
	{
		qDebug() << "回复ACK包失败";
		return;
	}

	info = "握手连接[3]:(Client:" + QString::fromUtf8(uint_to_addr(pip_header->saddr)) + ")--->(Server:" + QString::fromUtf8(uint_to_addr(pip_header->daddr)) + ")";
	emit myPacketHandle->packetStaticSignal(info);
	emit myPacketHandle->packetStaticSignal("连接成功........");
	connOK = 1;


	while (true)
	{
		if (isShouldReply==true || btnDisconnReply ==true)
			break;
		Sleep(100);
	}

	if (disconnFlag == false) {


		//发送fin回复的ack包  
		ptcp_header->ack = 1;
		ptcp_header->seq = htonl(next_seq);
		ptcp_header->ack_seq = htonl(next_ack_seq);
		ptcp_header->check = 0;
		ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));
		isShouldReply = false;
		if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
		{
			qDebug() << "断开连接：发送FIN回复的ack包";
			return;
		}
		info = "挥手断开[2]:(Client(被动)->Server)";
		emit myPacketHandle->packetStaticSignal(info);

		//接着发送一个fin, ack包  
		ptcp_header->ack = 1;
		ptcp_header->fin = 1;
		ptcp_header->seq = htonl(next_seq);
		ptcp_header->ack_seq = htonl(next_ack_seq);
		ptcp_header->check = 0;
		ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));
		step = 2;
		if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
		{
			qDebug() << "断开连接：发送FIN、ACK包";
			return;
		}
		info = "挥手断开[3]:(Client(被动)->Server)";
		emit myPacketHandle->packetStaticSignal(info);
		while (true)
		{
			if (isShouldReply)
				break;
			Sleep(100);
		}
	}
	else {
		isShouldReply = false;
		next_seq = 0x12345678;
		// 主动断开连接
		ptcp_header->ack = 1;
		ptcp_header->fin = 1;
		ptcp_header->seq = htonl(next_seq);
		ptcp_header->ack_seq = htonl(next_ack_seq);
		ptcp_header->check = 0;
		ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));
		if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
		{
			qDebug() << "主动断开第一步失败";
			return;
		}
		info = "挥手断开[1]:(Client(主动)->Server)";
		emit myPacketHandle->packetStaticSignal(info);
		while (true)
		{
			if (isShouldReply)
				break;
			Sleep(100);
		}

		ptcp_header->ack = 1;
		ptcp_header->fin = 0;
		ptcp_header->seq = htonl(next_seq);
		ptcp_header->ack_seq = htonl(next_ack_seq);
		ptcp_header->check = 0;
		ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));
		if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
		{
			qDebug() << "主动断开第四步失败";
			return;
		}
		info = "挥手断开[4]:(Client(主动)->Server)";
		emit myPacketHandle->packetStaticSignal(info);
		emit myPacketHandle->packetStaticSignal("断开连接.....");
		pcap_breakloop(adhandle);
		emit myPacketHandle->connStatusStaticSignal(1);

	}

}

void PacketHandle::my_pcap_handler(u_char * user, const pcap_pkthdr * pkt_header, const u_char * pkt_data)
{
	ether_header* pe_header = (ether_header*)pkt_data;

	if (pe_header->ether_type == htons(ETHERTYPE_IP))
	{
		ip_header* p_ip_header = (ip_header*)(pkt_data + sizeof(ether_header));

		//IP地址检验  
		if (p_ip_header->protocol == IPPROTO_TCP &&
			(p_ip_header->saddr == inet_addr(m_DSTIP) && p_ip_header->daddr == inet_addr(m_SRCIP)))
		{
			tcp_header* ptcpHeader = (tcp_header*)(pkt_data + sizeof(ether_header) + p_ip_header->ihl * 4);

			//端口检验  (处理连接和断开的数据包) 
			if (ptcpHeader->dest == htons(m_DSTPORT) || ptcpHeader->source == htons(m_DSTPORT))
			{
				//打印信息  

				//printf("[%s:%d \t-> ", uint_to_addr(p_ip_header->saddr), ntohs(ptcpHeader->source));
				//printf("%s:%d] len = %u type: ", uint_to_addr(p_ip_header->daddr), ntohs(ptcpHeader->dest),
				//	ntohs(p_ip_header->tot_len) - sizeof(ip_header) - sizeof(tcp_header));
				if (ptcpHeader->syn == 1) qDebug() << "SYN =  " << ntohl(ptcpHeader->seq);
				if (ptcpHeader->ack == 1) qDebug() << "ACK =  " << ntohl(ptcpHeader->ack_seq);
				if (ptcpHeader->fin == 1) qDebug() << "FIN =  " << ntohl(ptcpHeader->seq);
				if (ptcpHeader->rst == 1) {
					qDebug() << "RST "; 
					isRST = 1;}
				else
				{
					isRST = 0;
				}
				if (ptcpHeader->psh == 1) qDebug() << "PSH ";


				if (step == 0 && ptcpHeader->syn == 1 && ptcpHeader->ack == 1 && ptcpHeader->ack_seq == htonl(next_seq + 1))
				{

					// 若接收的是握手连接第二阶段的数据包 则开始编辑下一次要发送的数据包

					QString info = "握手连接[2]:(Server:"+ QString::fromUtf8(uint_to_addr(p_ip_header->saddr)) +")--->(Client:"+ QString::fromUtf8(uint_to_addr(p_ip_header->daddr)) +")";
					emit myPacketHandle->packetStaticSignal(info);
					next_ack_seq = htonl(ptcpHeader->seq) + 1;
					next_seq = htonl(ptcpHeader->ack_seq);
					isShouldReply = true;

				}
				else if (connOK == 1 && disconnFlag == false && step == 1 && ptcpHeader->fin == 1 && ptcpHeader->ack == 1)
				{

					QString info = "挥手断开[1]:(Server->Client(被动))";
					emit myPacketHandle->packetStaticSignal(info);
					next_ack_seq = htonl(ptcpHeader->seq) + 1;
					next_seq = htonl(ptcpHeader->ack_seq);
					isShouldReply = true;
				}

				else if (connOK == 1 && disconnFlag == false && step == 2 && ptcpHeader->ack == 1 && htonl(ptcpHeader->ack_seq) == next_seq+1 && htonl(ptcpHeader->seq) == next_ack_seq)
				{
					QString info = "挥手断开[4]:(Server->Client(被动))";
					emit myPacketHandle->packetStaticSignal(info);
					emit myPacketHandle->packetStaticSignal("断开连接....");
					isShouldReply = true;
					pcap_breakloop(adhandle);
					emit myPacketHandle->connStatusStaticSignal(1);

				}

				else if (connOK == 1 && disconnFlag == true && fin_count==1 && ptcpHeader->ack == 1 && ptcpHeader->fin == 0 && htonl(ptcpHeader->ack_seq) == next_seq + 1 && htonl(ptcpHeader->seq) == next_ack_seq)
				{
					QString info = "挥手断开[2]:(Server->Client(主动))";
					fin_count += 1;
					emit myPacketHandle->packetStaticSignal(info);
				}

				else if (connOK == 1 && disconnFlag == true && fin_count == 2 && ptcpHeader->ack == 1 && ptcpHeader->fin == 1 && htonl(ptcpHeader->ack_seq) == next_seq + 1 && htonl(ptcpHeader->seq) == next_ack_seq)
				{
					QString info = "挥手断开[3]:(Server->Client(主动))";
					emit myPacketHandle->packetStaticSignal(info);
					next_ack_seq = htonl(ptcpHeader->seq) + 1;
					next_seq = htonl(ptcpHeader->ack_seq);
					isShouldReply = true;
				}

			}
		}
	}



}

unsigned short PacketHandle::do_check_sum(void * buffer, int len)
{
	char buffer2[640] = { 0 };
	psd_header* psd = (psd_header*)buffer2;
	psd->sourceip = inet_addr(m_SRCIP);
	psd->destip = inet_addr(m_DSTIP);
	psd->ptcl = IPPROTO_TCP;
	psd->plen = htons(sizeof(tcp_header));

	memcpy(buffer2 + sizeof(psd_header), buffer, sizeof(tcp_header));

	return in_cksum((u_int16_t*)buffer2, sizeof(psd_header) + sizeof(tcp_header));
}

char * PacketHandle::uint_to_addr(u_int addr)
{
	in_addr inaddr;
	inaddr.S_un.S_addr = addr;
	return inet_ntoa(inaddr);
}

unsigned short PacketHandle::in_cksum(unsigned short * buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

void PacketHandle::packetStaticSlot(QString info)
{
	emit myPacketHandle->packetSignal(info);
}
void PacketHandle::connStatusStaticSlot(int connFlag)
{
	emit myPacketHandle->connStatusSignal(1);
}

void PacketHandle::getMsg(QString msg)
{
	qDebug() << "接收到消息了，消息为" << msg;
	my_msg = msg;
	unsigned long q = _beginthread(send_msg_packet, 0, NULL);
}

void PacketHandle::send_msg_packet(void *arg)
{
	//三次握手不含数据  
	char tcp_buffer[566] = { 0 };  //14 以太网头部, 20 ip头, 20+512 tcp头, 没有其它数据  

	ether_header* pether_header = (ether_header*)tcp_buffer;
	ip_header* pip_header = (ip_header*)(tcp_buffer + sizeof(ether_header));
	tcp_header* ptcp_header = (tcp_header*)(tcp_buffer + sizeof(ether_header) + sizeof(ip_header));


	//设置以太网头部  
	//所有MAC位置1  
	unsigned char mac[] = { 80,194,232,170,161,207 };
	memcpy(pether_header, mac, 6);
	//memset(pether_header, 1, 12);
	pether_header->ether_type = htons(ETHERTYPE_IP);

	//设置IP头  
	pip_header->ihl = sizeof(ip_header) / 4;
	pip_header->version = 4;
	pip_header->tos = 0;
	pip_header->tot_len = htons(sizeof(tcp_buffer) - sizeof(ether_header)); //12288  
	pip_header->id = 616;                                         //616  
	pip_header->frag_off = 64;
	pip_header->ttl = 128;
	pip_header->protocol = IPPROTO_TCP;
	pip_header->check = 0;
	pip_header->saddr = inet_addr(m_SRCIP);
	pip_header->daddr = inet_addr(m_DSTIP);
	pip_header->check = in_cksum((u_int16_t*)pip_header, sizeof(ip_header));

	//设置TCP头  
	ptcp_header->source = htons(m_SRCPORT);
	ptcp_header->dest = htons(m_DSTPORT);
	ptcp_header->seq = htonl((unsigned int)0x42345678);
	ptcp_header->ack_seq = htonl((unsigned int)0);
	ptcp_header->doff = sizeof(tcp_header) / 4;
	ptcp_header->res1 = 0;
	ptcp_header->res2 = 0;
	ptcp_header->fin = 0;
	ptcp_header->syn = 0;
	ptcp_header->rst = 0;
	ptcp_header->psh = 1;
	ptcp_header->ack = 1;
	ptcp_header->urg = 0;
	ptcp_header->window = 65535;
	ptcp_header->check = 0;
	ptcp_header->urg_ptr = 0;

	// 数据部分(测试)
	u_char data[512];

	QByteArray utf8Bytes = my_msg.toUtf8();
	char* temp_msg = utf8Bytes.data();

	memset(data, 0, sizeof(data));
	memcpy(ptcp_header->data, temp_msg, strlen(temp_msg));

	ptcp_header->check = do_check_sum(ptcp_header, sizeof(tcp_header));


	if (pcap_sendpacket(adhandle, (const u_char*)tcp_buffer, sizeof(tcp_buffer)) == -1)
	{
		qDebug() << "发送聊天数据包失败！";
		return;
	}
}