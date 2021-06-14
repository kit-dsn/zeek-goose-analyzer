
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginGoose)

include(ZeekPlugin)

zeek_plugin_begin(PA Goose)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/GooseAnalyzer.cc)
zeek_plugin_cc(src/gooseData.cc)
zeek_plugin_pac(src/goose.pac src/gooseInteger.pac src/asn1BitString.pac src/goose-protocol.pac src/gooseData.pac src/gooseFloat.pac)
zeek_plugin_bif(src/events.bif)
zeek_plugin_dist_files(README.md COPYING VERSION)
zeek_plugin_end()
