module GOOSE;

export {
	## Record holding information relevant for any GOOSE message.
	type GOOSE::PacketInfo : record {
		destination : string; ##< Destination MAC address	
		source : string; ##< Source MAC address	
		captureTime : double; ##< Time in seconds at which the GOOSE packet was captured. 0.0s is Bro start time.
	};

	## Measurement of time
	type GOOSE::UTCTime : record {
		## The number of seconds elapsed since 0h on January the 1rst,
		## 1970
		secondsSince1970 : count;
		## The number of nanoseconds since the last whole second
		nanoseconds	 : count;
	};


	## Record representing the object Data described in IEC 61850.
	##
	## The official type held by this record is represented by the
	## field "officialType". It is the ASN.1 tag parsed at the
	## beginning of the Data. There is no 1-on-1 correspondance
	## between the official type and the underlying type of the 
	## data actually held by the record, since some different
	## official types lead to having to store the same type of data
	## (e.g. bit-string and boolean-array).
	## Only one of the optional fields of a GOOSE::Data contains a
	## value.
	type GOOSE::Data : record {
		## The tag parsed at the beginning of the Data as it is
		## described in the GOOSE standard. Its value is between
		## 0x81 and 0x91.
		officialType: count;

		boolVal     : bool &optional;
		intVal      : int &optional;
		uintVal     : count &optional;
		realVal     : double &optional;
		bitStringVal: vector of bool &optional;
		stringVal   : string &optional;
		timeVal     : GOOSE::UTCTime &optional;
	} &redef;

	type GOOSE::SequenceOfData : vector of GOOSE::Data;

	# The Bro scripting language handles type recursion only through
	# redef.
	redef record GOOSE::Data += {
		arrayVal: GOOSE::SequenceOfData &optional;
	};

	## The main object of GOOSE
	type GOOSE::PDU : record {
		gocbRef          : string;
		timeAllowedToLive: count;
		datSet		 : string;
		goID		 : string &optional;
		t		 : GOOSE::UTCTime;
		stNum		 : count;
		sqNum		 : count;
		test		 : bool;
		confRev		 : count;
		ndsCom		 : bool;
		numDatSetEntries : count;
		allData		 : GOOSE::SequenceOfData;
	};

	global GOOSE::ether_types: set[count] = {0x88b8, 0x88b9} &redef;
}
