module GOOSE;

event zeek_init() &priority=20
	{
	for ( id in GOOSE::ether_types )
		PacketAnalyzer::register_packet_analyzer(
			PacketAnalyzer::ANALYZER_ETHERNET,
			id, PacketAnalyzer::ANALYZER_GOOSE);
		PacketAnalyzer::register_packet_analyzer(
			PacketAnalyzer::ANALYZER_VLAN,
			id, PacketAnalyzer::ANALYZER_GOOSE);
	}
