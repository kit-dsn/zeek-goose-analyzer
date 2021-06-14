
#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::PA_Goose {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
