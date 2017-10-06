#ifndef PACKETPP_IPV6EXTHEADER_LAYER
#define PACKETPP_IPV6EXTHEADER_LAYER

#include "Layer.h"
#include "IpAddress.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct ip6_exthdr
	 * Represents a generic IPv6 extension header
	 */
#pragma pack(push, 1)
	struct ip6_exthdr {
		/** Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes */
		uint8_t nextHeader;
		/** Length of the extension header in 8-octet units, not including the first 8 octets */
		uint8_t extHeaderLen;
		/** Data */
		uint8_t data[6];
	};
#pragma pack(pop)
	
	/**
	 * @struct ip6_exthdr
	 * Represents a IPv6 fragment header
	 */
#pragma pack(push, 1)
	struct ip6_fraghdr {
		/** Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes */
		uint8_t nextHeader;
		/** Reserved field, should be set to 0 */
		uint8_t reserved;
		/** Offset 13 bits, 2 reseved, M flag */
		uint16_t offlg;
		/** Identification */
		uint32_t id;
	};
#pragma pack(pop)	


	/**
	 * @class IPv6ExtHeaderLayer
	 * Represents an IPv6 Extension header layer
	 */
	class IPv6ExtHeaderLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ip6_hdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IPv6ExtHeaderLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new IPv6 extension header with empty fields
		 */
		IPv6ExtHeaderLayer();

		/**
		 * Get a pointer to the IPv6 extension header. 
		 * Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref ip6_exthdr
		 */
		inline ip6_exthdr* getIPv6ExtHeader() { return (ip6_exthdr*)m_Data; };

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of extension header
		 */
		inline size_t getHeaderLen() { return 8*(1+getIPv6ExtHeader()->extHeaderLen); }

		/**
		 * Calculate the following fields:
		 * - 
		 */
		void computeCalculateFields();

		std::string toString();

		OsiModelLayer getOsiModelLayer() { return OsiModelNetworkLayer; }

	private:
		void initLayer();
	};

} // namespace pcpp

#endif /* PACKETPP_IPV6EXTHEADER_LAYER */
