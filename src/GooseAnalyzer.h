#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::PA_Goose {

class GooseAnalyzer : public Analyzer {
public:
	GooseAnalyzer();
	~GooseAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, zeek::Packet* packet) override;

	static AnalyzerPtr Instantiate()
		{
		return std::make_shared<GooseAnalyzer>();
		}

	static StringVal* EthAddrToStr(const u_char* addr);

protected:
	void Corrupted(const char* string);
};

}
