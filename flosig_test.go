package flosig

import (
	"testing"

	"github.com/bitspill/flod/chaincfg"
)

func TestCheckSignature(t *testing.T) {
	testCases := []struct {
		name  string
		addr  string
		sig   string
		msg   string
		net   *chaincfg.Params
		coin  string
		valid bool
	}{
		{
			"main net p2pkh ok",
			"FDxa2dUXPw592svsebdHfGRHxB46DKWVUy",
			"IMjnGVBNW4kvoSITwijwYkrguszkyMQ08TBNu9wvRiVZB3f+L8Me1gkkK30LT9EO2xyMj0lFHORkSi/zM3cOTF0=",
			"Flo signed message test",
			&chaincfg.MainNetParams,
			"Florincoin",
			true,
		},
		{
			"main net p2pkh !ok",
			"FDxa2dUXPw592svsebdHfGRHxB46DKWVUy",
			"IMjnGVBNW4kvoSITwijwYkrguszkyMQ08TBNu9wvRiVZB3f+L8Me1gkkK30LT9EO2xyMj0lFHORkSi/zM3cOTF0=",
			"Flo signed message test.",
			&chaincfg.MainNetParams,
			"Florincoin",
			false,
		},
		{
			"test net p2pkh ok",
			"oWPVMaVa5S3WmQfaSzB3sgJ5EZv2im98XK",
			"H4nt3If+Hapgdw+MuaF9v8YOPLuT0fAco+UIIXlsPLJjEMw3+HIGHQUIjMNhuIU5XK3TVBlLMPixl+STbb0mhsw=",
			"Flo signed message test",
			&chaincfg.TestNet3Params,
			"Florincoin",
			true,
		},
		{
			"btc main net p2pkh ok",
			"1PVdqQygncV32a5YMWUmfEz2h3CqdHfXJe",
			"G25OicB3g46g9kZ0dGOI8+d9ZTlGrH8yKbCa5Xcd10UHcXZ0NRncgwCsKKGyXkU2+BLy0aq3013a0dTFfWf6mDQ=",
			"Bitcoin signed message test",
			&chaincfg.BtcMainNetParams,
			"Bitcoin",
			true,
		},
		{
			"flo main net p2wpkh ok",
			"exniEyscjPy354T1PBETuL9MF4bDWbcqmH",
			"JJqHgNaorUWXdkFsz5fyonAJ58Zk5xFqHDGx67dbJIBRH/B04xHWA5NRZRrZ9bFM12FUkR1X3VI0khrGm1As7NQ=",
			"Flo P2WPKH signed message test",
			&chaincfg.MainNetParams,
			"Florincoin",
			true,
		},
		{
			"flo main net p2wpkh 2 ok",
			"ex5vcFARbURRZk1kN8ocd1YiTagjPooiqU",
			"I/gfPFvSemCw8cjSqETRYqEhLqo95s7WUu6Knu7nnwRebejYrZBzHUFSCmVUr5WMmY8qlNZnB8uoNqP3SKAkL3k=",
			"Example message",
			&chaincfg.MainNetParams,
			"Florincoin",
			true,
		},
		{
			"ltc main net p2wpkh ok",
			"MFoQRU1KQq365Sy3cXhix3ygycEU4YWB1V",
			"JG0W/aZi+cGgJrx/vhQmxdho9asZ+Q7PFoCs9FM4qHUYaivphYaXbjZDO8vUzIH8Xo1XQB3S/3z17SLYKU8rD/g=",
			"Example message",
			&chaincfg.LtcMainNetParams,
			"Litecoin",
			true,
		},
		{
			"btc main p2wpkh ok",
			"3CwYaeWxhpXXiHue3ciQez1DLaTEAXcKa1",
			"JJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=",
			"This is an example of a signed message.",
			&chaincfg.BtcMainNetParams,
			"Bitcoin",
			true,
		},
		{
			"btc testnet p2wpkh ok",
			"2N4VkePSzKH2sv5YBikLHGvzUYvfPxV6zS9",
			"JJ4j7fDk5H/x3sJ/Ms14xQ507wGO6Kat81rhfHqbDdlvSLST/X26sD77b0OcY4PJUjs7vF8afRWKavkKsVTpvoA=",
			"This is an example of a signed message.",
			&chaincfg.BtcTestNet3Params,
			"Bitcoin",
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := CheckSignature(tc.addr, tc.sig, tc.msg, tc.coin, tc.net)
			if err != nil {
				t.Error(err)
			}

			if ok != tc.valid {
				t.Errorf("got %t, expected %t", ok, tc.valid)
			}
		})
	}
}
