#ifndef PACKETPP_ICMPV6_LAYER
#define PACKETPP_ICMPV6_LAYER

#include <Layer.h>
#include <IPv6Layer.h>
#include <IcmpLayer.h>
#ifdef _MSC_VER
#include <Winsock2.h>
#else
#include <sys/time.h>
#endif
#include <vector>


/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
     * @TODO review
	 * An enum of all supported ICMPv6 message types
	 */
	enum Icmpv6MessageType
	{
        //@TODO docs
		/** ICMPV6 destination unreachable message */
		ICMPV6_DEST_UNREACHABLE     = 1,
		/** ICMPV6 packet too big message */
		ICMPV6_PACKET_TOO_BIG       = 2,
		/** ICMPV6 time exceeded message */
		ICMPV6_TIME_EXCEEDED        = 3,
		/** ICMPV6 parameter problem message */
		ICMPV6_PARAM_PROBLEM        = 4,
        /** ICMPv6 echo request message */
        ICMPV6_ECHO_REQUEST         = 128,
        ICMPV6_ECHO_REPLY           = 129,
        ICMPV6_MULTICAST_LIS_QUERY  = 130,
        ICMPV6_MULTICAST_LIS_REPORT = 131,
        ICMPV6_MULTICAST_LIS_DONE = 132,
        ICMPV6_ROUTER_SOL = 133,
        ICMPV6_ROUTER_ADV = 134,
        ICMPV6_NEIGHBOR_SOL = 135,
        ICMPV6_NEIGHBOR_ADV = 136,
        ICMPV6_REDIRECT = 137,
        ICMPV6_ROUTER_RENUMBER = 138,
        ICMPV6_NODE_INFO_QUERY = 139,
        ICMPV6_NODE_INFO_RESPONSE = 140,
        ICMPV6_INV_NEIGHBOR_DISCOVERY_SOL = 141,
        ICMPV6_INV_NEIGHBOR_DISCOVERY_ADV = 142,
        ICMPV6_MUTICAST_LIS_REPORT_V2 = 143,
        ICMPV6_HOME_AGENT_ADDR_DISCOV_REQUEST = 144,
        ICMPV6_HOME_AGENT_ADDR_DISCOV_REPLY = 145,
        ICMPV6_MOBILE_PREFIX_SOL = 146,
        ICMPV6_MOBILE_PREFIX_ADV = 147,
        ICMPV6_CERT_PATH_SOL = 148,
        ICMPV6_CERT_PATH_ADV = 149,
        ICMPV6_MULTICAST_ROUTER_ADV = 151,
        ICMPV6_MULTICAST_ROUTER_SOL = 152,
        ICMPV6_MULTICAST_ROUTER_TERM = 153,
        ICMPV6_FIMPV6 = 154,
        ICMPV6_RPL_CONTROL = 155,
        ICMPV6_ILNPV6_LOCATOR_UPDATE = 156,
        ICMPV6_DUPLICATE_ADDR_REQUEST = 157,
        ICMPV6_DUPLICATE_ADDR_CONFIRM = 158,
        ICMPV6_MPL_CONTROL = 159,
        ICMPV6_UNSUPPORTED = 255
	};

	/**
     * @TODO review
	 * An enum for all possible codes for a destination unreachable message type
	 * Documentation is taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_version_6
	 */
	enum Icmpv6DestUnreachableCodes
	{
		/** @TODO docs*/
        Icmpv6NoRouteToDestination = 0,
		Icmpv6CommunicationProhibited = 1,
		Icmpv6BeyondScopeOfSourceAddress = 2,
		Icmpv6AddressUnreachable = 3,
        Icmpv6PortUnreachable = 4,
        Icmpv6SourceAddrFailedPolicy = 5,
        Icmpv6RejectRouteToDest = 6,
        Icmpv6ErrorInSourceRoutingHeader = 7
	};

    
	/**
	 * @class Icmpv6Layer
	 * Represents an ICMPv6 protocol layer (for IPv6 only)
	 */
	class Icmpv6Layer : public Layer
	{
	private:

		bool cleanIcmpv6Layer();

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		Icmpv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ICMPv6; }

		/**
		 * An empty constructor that creates a new layer with an empty ICMP header without setting the ICMP type or ICMP data.
		 * Call the set*Data() methods to set ICMP type and data
		 */
		Icmpv6Layer();

		virtual ~Icmpv6Layer() {}

		/**
		 * Get a pointer to the basic ICMPv6 header (same as ICMP header).
		 * Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref icmphdr
		 */
		inline icmphdr* getIcmpv6Header() { return (icmphdr*)m_Data; };

		/**
		 * @return The ICMPv6 message type
		 */
		Icmpv6MessageType getMessageType();

		/**
		 * @param[in] type Type to check
		 * @return True if the layer if of the given type, false otherwise
		 */
		bool isMessageOfType(Icmpv6MessageType type);



		// implement abstract methods

		/**
		 * @TODO check and implement
		 * ICMP messages of types: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED, ICMP_REDIRECT, ICMP_PARAM_PROBLEM
		 * have data that contains IPv4 header and some L4 header (TCP/UDP/ICMP). This method parses these headers as separate
		 * layers on top of the ICMP layer
		 */
		void parseNextLayer();

		/**
		 * @TODO should ->
		 * @return The ICMP header length. This length varies according to the ICMP message type. This length doesn't include
		 * IPv4 and L4 headers in case ICMP message type are: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED,
		 * ICMP_REDIRECT, ICMP_PARAM_PROBLEM
		 * 
		 * @TODO returns always sizeof(icmphdr)
		 */
		size_t getHeaderLen();

		/**
		 * @TODO verify
		 * Calculate ICMP checksum field
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_ICMPV6_LAYER */
