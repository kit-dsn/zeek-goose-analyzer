# @TEST-EXEC: zeek -r $TRACES/AS2.pcapng %INPUT > out
# @TEST-EXEC: btest-diff out

@load PA/goose
@load PA/goose/counter-monitoring
