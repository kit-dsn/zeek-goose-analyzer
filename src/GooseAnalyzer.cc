#include "GooseAnalyzer.h"
#include <zeek/Event.h>
#include <zeek/Reporter.h>

#include "events.bif.h"
#include "goose_pac.h"
#include "gooseData.h"

using namespace zeek::packet_analysis::PA_Goose;

GooseAnalyzer::GooseAnalyzer()
	: zeek::packet_analysis::Analyzer("GOOSE")
	{
	}

static zeek::IntrusivePtr<zeek::RecordVal> packet_info_from_packet(const zeek::Packet &pkt) {
	auto data = pkt.data;
	auto info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::GOOSE::PacketInfo);

	// MAC Adresses:
	info->Assign(0, GooseAnalyzer::EthAddrToStr(data)); // Destination
	info->Assign(1, GooseAnalyzer::EthAddrToStr(data+6)); // Source 

	// Reception time:
	info->Assign(2, zeek::make_intrusive<zeek::DoubleVal>(pkt.time));

	return info;
}

bool GooseAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet)
	{
	binpac::GOOSE::GOOSE_Message msg;

	try {
		msg.Parse(data, data + len);
	}
	catch(binpac::Exception & e) {
		std::string errmsg("GOOSE packet parsing generated this error :\n");
		errmsg += e.c_msg();
		errmsg += "\n";

		this->Corrupted(errmsg.c_str());

		return false;
	}

	auto packetInfo = packet_info_from_packet(*packet);

	// generating the event
	if(msg.PDU_case_index() == binpac::GOOSE::GOOSE_PDU && goose_message)
		{
		event_mgr.Enqueue(goose_message,
				packetInfo,
				goosePdu_as_val(msg.goosePdu()));
		}

	return true;
	}

zeek::StringVal* GooseAnalyzer::EthAddrToStr(const u_char* addr)
	{
	char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return new StringVal(buf);
	}

void GooseAnalyzer::Corrupted(const char* msg)
	{
	reporter->Weird(msg);
	}
