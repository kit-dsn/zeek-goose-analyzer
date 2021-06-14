%include binpac.pac
%include zeek.pac

%extern{
#include "goose_pac.h"
#include "gooseData.h"

#include "events.bif.h"
%}


analyzer GOOSE withcontext {
};

%include goose-protocol.pac

# === Exporting to BroVal objects ===

%header{
	zeek::RecordValPtr goosePdu_as_val(IECGoosePdu* pdu);
%}

%code{
	zeek::RecordValPtr goosePdu_as_val(IECGoosePdu* pdu)
		{
		auto result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::GOOSE::PDU);

		result->Assign(0, bytestring_to_val(${pdu.gocbRef.str}));
		result->Assign(1, zeek::val_mgr->Count(${pdu.timeAllowedToLive.gooseUInt.val}));
		result->Assign(2, bytestring_to_val(${pdu.datSet.str}));
		// goID is optional
		if(${pdu.has_goID}) // check if pointer is NULL
		{
			result->Assign(3, bytestring_to_val(${pdu.goIDAndT.goID}));
			result->Assign(4, gooseT_as_val(${pdu.goIDAndT.t.val}));
		}
		else
			result->Assign(4, gooseT_as_val(${pdu.t}));

		result->Assign(5, zeek::val_mgr->Count(${pdu.stNum.gooseUInt.val}));
		result->Assign(6, zeek::val_mgr->Count(${pdu.sqNum.gooseUInt.val}));

		if(${pdu.testAndConfRev.boolValIsPresent})
			result->Assign(7, zeek::val_mgr->Bool(${pdu.testAndConfRev.boolVal}));

		result->Assign(8, zeek::val_mgr->Count(${pdu.testAndConfRev.uintVal}));

		if(${pdu.ndsComAndNumDatSetEntries.boolValIsPresent})
			result->Assign(9, zeek::val_mgr->Bool(${pdu.ndsComAndNumDatSetEntries.boolVal}));

		result->Assign(10, zeek::val_mgr->Count(${pdu.ndsComAndNumDatSetEntries.uintVal}));

		result->Assign(11, goose_data_array_as_val(${pdu.allData}));

		return result;
		}
%}