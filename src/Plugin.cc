
#include "Plugin.h"
#include <zeek/packet_analysis/Component.h>

#include "GooseAnalyzer.h"

namespace zeek::plugin::PA_Goose {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::packet_analysis::Component("GOOSE",
	                 zeek::packet_analysis::PA_Goose::GooseAnalyzer::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "PA::GOOSE";
	config.description = "A GOOSE analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}

}
