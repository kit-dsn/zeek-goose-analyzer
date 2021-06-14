# @TEST-EXEC: zeek -r $TRACES/integer.pcap %INPUT > integer.log
# @TEST-EXEC: zeek -r $TRACES/all_arrays.pcap %INPUT > all_arrays.log
# @TEST-EXEC: btest-diff integer.log
# @TEST-EXEC: btest-diff all_arrays.log

@load PA/goose

function bool_to_string(val: bool): string
{
	if(val)
		return "true";
	else
		return "false";
}

function print_goose_data_array(datarray: GOOSE::SequenceOfData, indent: string &default = "    ")
{
	for (d in datarray)
	{
		local dat = datarray[d];

		# Highlighting the 2 ways to test for the type of GOOSE::Data :

		# The first way is using the tag (aka officialType)
		if(dat$officialType == GOOSE::GOOSE_DATA_TYPE_BOOLEAN)
			print fmt("%sBoolean Value : %s", indent, bool_to_string(dat$boolVal));

		# The second way is to test the presence of the underlying data. It's safer
		# since in case of a malformed packet, the record could contain no actual data.
		else if(dat?$bitStringVal)
		{
			print indent + "Bit-String Value:";
			local indent_plus_1 = "    " + indent;
			for(bs in dat$bitStringVal)
			{
				print fmt("%s%s", indent_plus_1, bool_to_string(dat$bitStringVal[bs]));
			}
		}
		else if(dat?$intVal)
			print fmt("%sInteger value: %d", indent, dat$intVal);
		else if(dat?$uintVal)
			print fmt("%sUnsigned integer value: %d", indent, dat$uintVal);
		else if(dat?$realVal)
			print fmt("%sReal value: %f", indent, dat$realVal);
		else if(dat?$stringVal)
			print fmt("%sString value: %s", indent, dat$stringVal);
		else if(dat?$timeVal)
		{
			print fmt("%sTime value: %ds %dns", indent, dat$timeVal$secondsSince1970, dat$timeVal$nanoseconds);
		}
		else if(dat?$arrayVal)
		{
			print indent + "Data array:";

			# Recursive call :
			print_goose_data_array(dat$arrayVal, "    " + indent);
		}
		else
			print fmt("%sMalformed data of tag: %d", indent, dat$officialType);
	}
}

function print_goose_content(pdu: GOOSE::PDU)
{
	print fmt("gocbRef: %s", pdu$gocbRef);
	print fmt("timeAllowedToLive: %d.", pdu$timeAllowedToLive);
	print fmt("datSet: %s", pdu$datSet);
	if(pdu?$goID)
		print fmt("It has a goID: %s", pdu$goID);
	print fmt("t: %ds %dns", pdu$t$secondsSince1970, pdu$t$nanoseconds);
	print fmt("stNum: %d ; sqNum: %d", pdu$stNum, pdu$sqNum);
	print fmt("test: %s ; ndsCom: %s", bool_to_string(pdu$test), bool_to_string(pdu$ndsCom));
	print fmt("confRev: %d", pdu$confRev);
	print fmt("numDatSetEntries: %d", pdu$numDatSetEntries);

	print "allData:";
	print_goose_data_array(pdu$allData);
	print "";
}

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
{
	print ">>> GOOSE message detected <<<";
	print info;
	print_goose_content(pdu);
}
