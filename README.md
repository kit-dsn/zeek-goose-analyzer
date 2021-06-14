# PA::GOOSE

Port of the GOOSE analyzer https://github.com/zeek/zeek/pull/76 into a packet analyzer.

## Installation

The plugin is based on Zeek 4.0's new packet analysis framework. Note that Zeek's plugin interface is in a rework which might cause deprecation warnings.

### Zeek Package Manager

TBD

### Manual Install

The following will compile and install the GOOSE plugin alongside Zeek:

	# ./configure && make && make install

If everything built and installed correctly, you should see this:

	# zeek -NN PA::GOOSE
	PA::GOOSE - A GOOSE analyzer (dynamic, version 0.1.0)
		[Packet Analyzer] GOOSE (ANALYZER_GOOSE)
		[Event] goose_message
		[Type] GOOSE::PacketInfo
		[Type] GOOSE::PDU
		[Type] GOOSE::UTCTime
		[Type] GOOSE::Data
		[Type] GOOSE::SequenceOfData


## Usage

For examples see the test cases in `tests/goose`.
