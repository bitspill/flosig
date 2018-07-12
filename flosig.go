// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package flosig

import (
	"bytes"
	"encoding/base64"
	"github.com/bitspill/flod/floec"
	"github.com/bitspill/flod/flojson"
	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/wire"
	"github.com/bitspill/floutil"
)

func CheckSignature(checkAddress string, checkSignature string, message string, coinName string, net *chaincfg.Params) (bool, error) {
	// Function body lifted from BTCD https://github.com/btcsuite/btcd/blob/807d344/rpcserver.go#L3607
	// Decode the provided address.
	addr, err := floutil.DecodeAddress(checkAddress, net)
	if err != nil {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCInvalidAddressOrKey,
			Message: "Invalid address or key: " + err.Error(),
		}
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*floutil.AddressPubKeyHash); !ok {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCType,
			Message: "Address is not a pay-to-pubkey-hash address",
		}
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(checkSignature)
	if err != nil {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCParse.Code,
			Message: "Malformed base64 encoding: " + err.Error(),
		}
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, coinName+" Signed Message:\n")
	wire.WriteVarString(&buf, 0, message)
	expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
	pk, wasCompressed, err := floec.RecoverCompact(floec.S256(), sig,
		expectedMessageHash)
	if err != nil {
		// Mirror Bitcoin Core behavior, which treats error in
		// RecoverCompact as invalid signature.
		return false, nil
	}

	// Reconstruct the pubkey hash.
	var serializedPK []byte
	if wasCompressed {
		serializedPK = pk.SerializeCompressed()
	} else {
		serializedPK = pk.SerializeUncompressed()
	}
	address, err := floutil.NewAddressPubKey(serializedPK,
		net)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in public key
		// reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return address.EncodeAddress() == checkAddress, nil
}
