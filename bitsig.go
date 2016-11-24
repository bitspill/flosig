// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bitsig_go

import (
	"bytes"
	"encoding/base64"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

func CheckSignature(checkAddress string, checkSignature string, message string, coinName string, net *chaincfg.Params) (bool, error) {
	// Function body lifted from BTCD https://github.com/btcsuite/btcd/blob/807d344/rpcserver.go#L3607
	// Decode the provided address.
	addr, err := btcutil.DecodeAddress(checkAddress, net)
	if err != nil {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "Invalid address or key: " + err.Error(),
		}
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*btcutil.AddressPubKeyHash); !ok {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCType,
			Message: "Address is not a pay-to-pubkey-hash address",
		}
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(checkSignature)
	if err != nil {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCParse.Code,
			Message: "Malformed base64 encoding: " + err.Error(),
		}
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, coinName+" Signed Message:\n")
	wire.WriteVarString(&buf, 0, message)
	expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
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
	address, err := btcutil.NewAddressPubKey(serializedPK,
		net)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in public key
		// reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return address.EncodeAddress() == checkAddress, nil
}
