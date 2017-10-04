#define LOG_MODULE PacketLogModuleIPv6ExtHeaderLayer

#include <IPv6ExtHeaderLayer.h>
#include <PayloadLayer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <GreLayer.h>
#include <Icmpv6Layer.h>
#include <string.h>
#include <IpUtils.h>

#include "Packet.h"


namespace pcpp
{

void IPv6ExtHeaderLayer::initLayer()
{
	m_DataLen = sizeof(ip6_exthdr);
	m_Data = new uint8_t[m_DataLen];
	m_Protocol = IPv6ExtHdr;
	memset(m_Data, 0, sizeof(ip6_exthdr));
}

IPv6ExtHeaderLayer::IPv6ExtHeaderLayer()
{
	initLayer();
}

void IPv6ExtHeaderLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(ip6_exthdr))
		return;

	ip6_exthdr* ipHdr = getIPv6ExtHeader();

	ProtocolType greVer = UnknownProtocol;

	uint8_t ipVersion = 0;

	switch (ipHdr->nextHeader)
	{
	case PACKETPP_IPPROTO_HOPOPTS:
	case PACKETPP_IPPROTO_ROUTING:
	case PACKETPP_IPPROTO_FRAGMENT:
	case PACKETPP_IPPROTO_AH:
	case PACKETPP_IPPROTO_DSTOPTS:
		m_NextLayer = new IPv6ExtHeaderLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_UDP:
		m_NextLayer = new UdpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_TCP:
		m_NextLayer = new TcpLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
    case PACKETPP_IPPROTO_ICMPV6:
        m_NextLayer = new Icmpv6Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);\
        break;
	case PACKETPP_IPPROTO_IPIP:
		ipVersion = *(m_Data + sizeof(ip6_hdr));
		if (ipVersion >> 4 == 4)
			m_NextLayer = new IPv4Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else if (ipVersion >> 4 == 6)
			m_NextLayer = new IPv6ExtHeaderLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	case PACKETPP_IPPROTO_GRE:
		greVer = GreLayer::getGREVersion(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr));
		if (greVer == GREv0)
			m_NextLayer = new GREv0Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else if (greVer == GREv1)
			m_NextLayer = new GREv1Layer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(m_Data + sizeof(ip6_hdr), m_DataLen - sizeof(ip6_hdr), this, m_Packet);
		return;
	}
}

void IPv6ExtHeaderLayer::computeCalculateFields()
{
// @TODO 
	//	ip6_exthdr* ipHdr = getIPv6ExtHeader();
//	ipHdr->payloadLength = htons(m_DataLen - sizeof(ip6_exthdr));
//	ipHdr->ipVersion = (6 & 0x0f);
//
//	if (m_NextLayer != NULL)
//	{
//		switch (m_NextLayer->getProtocol())
//		{
//		case TCP:
//			ipHdr->nextHeader = PACKETPP_IPPROTO_TCP;
//			break;
//		case UDP:
//			ipHdr->nextHeader = PACKETPP_IPPROTO_UDP;
//			break;
//		case ICMP:
//			ipHdr->nextHeader = PACKETPP_IPPROTO_ICMP;
//			break;
//		case GRE:
//			ipHdr->nextHeader = PACKETPP_IPPROTO_GRE;
//			break;
//		default:
//			break;
//		}
//	}
}

std::string IPv6ExtHeaderLayer::toString()
{
	return "IPv6 Extension Header Layer";
}

}// namespace pcpp
