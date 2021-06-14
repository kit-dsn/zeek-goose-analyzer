module GOOSE;

## Values of Status and Sequence Number
type GOOSE::CounterValues : record {
	sqNum: count;
	stNum: count;
};

## Counter stats per data set
global GOOSE::counter_stats: table[string] of CounterValues;

event goose_message(info: GOOSE::PacketInfo, pdu: GOOSE::PDU)
	{
	local ds: string = pdu$datSet;
	if ( ds !in counter_stats )
		{
		counter_stats[ds] = CounterValues(
			$sqNum = pdu$sqNum,
			$stNum = pdu$stNum);
		return;
		}

	# Check for increments > 1
	if ( pdu$sqNum > counter_stats[ds]$sqNum + 1 )
		print fmt("Sequence number jump for %s (%d -> %d)",
			ds, counter_stats[ds]$sqNum, pdu$sqNum);
	if ( pdu$stNum > counter_stats[ds]$stNum + 1 )
		print fmt("State number jump for %s (%d -> %d)",
			ds, counter_stats[ds]$stNum, pdu$stNum);

	# Update counters
	counter_stats[ds]$sqNum = pdu$sqNum;
	counter_stats[ds]$stNum = pdu$stNum;
	}

