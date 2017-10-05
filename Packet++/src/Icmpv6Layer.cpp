#define LOG_MODULE PacketLogModuleIcmpv6Layer

#include <Icmpv6Layer.h>
#include <PayloadLayer.h>
#include <Packet.h>
#include <IpUtils.h>
#include <Logger.h>
#include <sstream>
#include <string.h>
#if defined(WIN32) || defined(WINx64) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

namespace pcpp
{

Icmpv6Layer::Icmpv6Layer() : Layer()
{
	m_DataLen = sizeof(icmphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = ICMPv6;
}

Icmpv6MessageType Icmpv6Layer::getMessageType()
{
	uint8_t type = getIcmpv6Header()->type;
	if (type > 159)
		return ICMPV6_UNSUPPORTED;

	return (Icmpv6MessageType)type;
}

bool Icmpv6Layer::isMessageOfType(Icmpv6MessageType type)
{
	return (getMessageType() == type);
}

bool Icmpv6Layer::cleanIcmpv6Layer()
{
	// remove all layers after

	if (m_Packet != NULL)
	{
		Layer* layerToRemove = this->getNextLayer();
		while (layerToRemove != NULL)
		{
			Layer* temp = layerToRemove->getNextLayer();
			if (!m_Packet->removeLayer(layerToRemove))
				return false;
			layerToRemove = temp;
		}
	}


	// shorten layer to size of icmphdr

	size_t headerLen = this->getHeaderLen();
	if (headerLen > sizeof(icmphdr))
	{
		if (!this->shortenLayer(sizeof(icmphdr), headerLen - sizeof(icmphdr)))
			return false;
	}

	return true;
}


void Icmpv6Layer::parseNextLayer()
{
	Icmpv6MessageType type = getMessageType();
	size_t headerLen = 0;

	switch (type)
	{
	case ICMPV6_DEST_UNREACHABLE:
// @TODO make and review
//		headerLen = getHeaderLen();
//		if (m_DataLen - headerLen >= sizeof(iphdr))
//			m_NextLayer = new IPv4Layer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
//		return;
	/* as a workaround for different headers (echo req, echo reply etc,
	 * just make a payload layer with the rest of data
	 */
	default:
		headerLen = getHeaderLen();
		if (m_DataLen > headerLen)
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		return;
	}
}

size_t Icmpv6Layer::getHeaderLen()
{
	Icmpv6MessageType type = getMessageType();
	switch (type)
	{
	case ICMPV6_ECHO_REQUEST:
//        @TODO
	default:
		return sizeof(icmphdr);
	}
}

void Icmpv6Layer::computeCalculateFields()
{
	// calculate checksum
	getIcmpv6Header()->checksum = 0;

	size_t icmpLen = 0;
	Layer* curLayer = this;
	while (curLayer != NULL)
	{
		icmpLen += curLayer->getHeaderLen();
		curLayer = curLayer->getNextLayer();
	}

	ScalarBuffer<uint16_t> buffer;
	buffer.buffer = (uint16_t*)getIcmpv6Header();
	buffer.len = icmpLen;
	size_t checksum = compute_checksum(&buffer, 1);

	getIcmpv6Header()->checksum = htons(checksum);
}

std::string Icmpv6Layer::toString()
{
	std::string messageTypeAsString;
	Icmpv6MessageType type = getMessageType();
	switch (type)
	{
	case ICMPV6_DEST_UNREACHABLE:
		messageTypeAsString = "Destination unreachable";
		break;
    case ICMPV6_PACKET_TOO_BIG:
        messageTypeAsString = "Packet too big";
        break;
    case ICMPV6_TIME_EXCEEDED:
        messageTypeAsString = "Time exceeded";
        break;
    case ICMPV6_PARAM_PROBLEM:
        messageTypeAsString = "Parameter problem";
        break;
    case ICMPV6_ECHO_REQUEST:
        messageTypeAsString = "Echo (ping) request";
        break;
    case ICMPV6_ECHO_REPLY:
        messageTypeAsString = "Echo (ping) reply";
        break;
    case ICMPV6_MULTICAST_LIS_QUERY:
        messageTypeAsString = "Multicast listener query";
        break;
    case ICMPV6_MULTICAST_LIS_REPORT:
        messageTypeAsString = "Multicast listener report";
        break;
    case ICMPV6_MULTICAST_LIS_DONE:
        messageTypeAsString = "Multicast listener done";
        break;
    case ICMPV6_ROUTER_SOL:
        messageTypeAsString = "Router solicitation";
        break;
    case ICMPV6_ROUTER_ADV:
        messageTypeAsString = "Router advertisement";
        break;
    case ICMPV6_NEIGHBOR_SOL:
        messageTypeAsString = "Neighbor solicitation";
        break;
    case ICMPV6_NEIGHBOR_ADV:
        messageTypeAsString = "Neighbor advertisement";
        break;
    case ICMPV6_REDIRECT:
        messageTypeAsString = "Redirect";
        break;
    case ICMPV6_ROUTER_RENUMBER:
        messageTypeAsString = "Router renumbering";
        break;
    case ICMPV6_NODE_INFO_QUERY:
        messageTypeAsString = "ICMP node information query";
        break;
    case ICMPV6_NODE_INFO_RESPONSE:
        messageTypeAsString = "ICMP node information response";
        break;
    case ICMPV6_INV_NEIGHBOR_DISCOVERY_SOL:
        messageTypeAsString = "Inverse neighbor discovery solicitation message";
        break;
    case ICMPV6_INV_NEIGHBOR_DISCOVERY_ADV:
        messageTypeAsString = "Inverse neighbor discovery advertisement message";
        break;
    case ICMPV6_MUTICAST_LIS_REPORT_V2:
        messageTypeAsString = "Version 2 multicast listener report";
        break;
    case ICMPV6_HOME_AGENT_ADDR_DISCOV_REQUEST:
        messageTypeAsString = "Home agent address discovery request";
        break;
    case ICMPV6_HOME_AGENT_ADDR_DISCOV_REPLY:
        messageTypeAsString = "Home agent address discovery reply";
        break;
    case ICMPV6_MOBILE_PREFIX_SOL:
        messageTypeAsString = "Mobile prefix solicitation";
        break;
	case ICMPV6_MOBILE_PREFIX_ADV:
		messageTypeAsString = "Mobile prefix advertisement";
		break;
	case ICMPV6_CERT_PATH_SOL:
		messageTypeAsString = "Certification path solicitaion message";
		break;
	case ICMPV6_CERT_PATH_ADV:
		messageTypeAsString = "Certification path advertisement message";
		break;
	case ICMPV6_MULTICAST_ROUTER_ADV:
		messageTypeAsString = "Multicast Router Advertisement";
		break;
	case ICMPV6_MULTICAST_ROUTER_SOL:
		messageTypeAsString = "Multicast Router Solicitation";
		break;
	case ICMPV6_MULTICAST_ROUTER_TERM:
		messageTypeAsString = "Multicast Router Termination";
		break;
	case ICMPV6_FIMPV6:
		messageTypeAsString = "FMIPv6 Messages";
		break;
	case ICMPV6_RPL_CONTROL:
		messageTypeAsString = "RPL Control Message";
		break;
	case ICMPV6_ILNPV6_LOCATOR_UPDATE:
		messageTypeAsString = "ILNPv6 Locator Update Message";
		break;
	case ICMPV6_DUPLICATE_ADDR_REQUEST:
		messageTypeAsString = "Duplicate Address Request";
		break;
	case ICMPV6_DUPLICATE_ADDR_CONFIRM:
		messageTypeAsString = "Duplicate Address Confirmation";
		break;
	case ICMPV6_MPL_CONTROL:
		messageTypeAsString = "MPL Control Message";
		break;
	default:
		messageTypeAsString = "Unknown";
		break;
	}

	std::ostringstream typeStream;
	typeStream << (int)getIcmpv6Header()->type;

	return "ICMPv6 Layer, " + messageTypeAsString + " (type: " + typeStream.str() + ")";
}

} // namespace pcpp
