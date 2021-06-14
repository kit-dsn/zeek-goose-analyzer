# @TEST-EXEC: zeek -NN PA::GOOSE |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
