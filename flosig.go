// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package flosig

import (
	"bytes"
	"encoding/base64"

	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/floec"
	"github.com/bitspill/flod/flojson"
	"github.com/bitspill/flod/wire"
	"github.com/bitspill/floutil"
)

type keyType uint32

const (
	P2PKH keyType = iota
	P2WPKH
	P2WSH
)

func CheckSignature(checkAddress string, checkSignature string, message string, coinName string, net *chaincfg.Params) (bool, error) {
	// Function body largely lifted from BTCD with modifications for Trezor compatibility
	// https://github.com/btcsuite/btcd/blob/807d344/rpcserver.go#L3607
	// https://github.com/trezor/trezor-mcu/blob/19c7c8b/firmware/crypto.c#L151

	// Decode the provided address.
	addr, err := floutil.DecodeAddress(checkAddress, net)
	if err != nil {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCInvalidAddressOrKey,
			Message: "Invalid address or key: " + err.Error(),
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

	if len(sig) == 0 {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCParse.Code,
			Message: "Malformed signature",
		}
	}

	if sig[0] < 27 || sig[0] > 43 {
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCType,
			Message: "Invalid signature prefix",
		}
	}

	var kt keyType
	// pay-to-pubkey-hash (P2PKH)
	if sig[0] >= 27 && sig[0] <= 34 {
		kt = P2PKH
		if _, ok := addr.(*floutil.AddressPubKeyHash); !ok {
			return false, &flojson.RPCError{
				Code:    flojson.ErrRPCType,
				Message: "Address is not a pay-to-pubkey-hash address",
			}
		}
	}

	// pay-to-witness-pubkey-hash (P2WPKH) (base58)
	if sig[0] >= 35 && sig[0] <= 38 {
		kt = P2WPKH
		if _, ok := addr.(*floutil.AddressScriptHash); !ok {
			return false, &flojson.RPCError{
				Code:    flojson.ErrRPCType,
				Message: "Address is not a pay-to-witness-pubkey-hash address",
			}
		}
	}

	// pay-to-witness-script-hash (P2WSH) (bech32)
	if sig[0] >= 39 && sig[0] <= 42 {
		kt = P2WSH
		return false, &flojson.RPCError{
			Code:    flojson.ErrRPCType,
			Message: "Address of type pay-to-witness-script-hash not supported",
		}
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	_ = wire.WriteVarString(&buf, 0, coinName+" Signed Message:\n")
	_ = wire.WriteVarString(&buf, 0, message)
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

	var address floutil.Address

	switch kt {
	case P2PKH:
		address, err = floutil.NewAddressPubKey(serializedPK, net)
	case P2WPKH:
		address, err = floutil.NewAddressScriptHash(serializedPK, net)
		if err != nil {
			// Again mirror Bitcoin Core behavior, which treats error in public key
			// reconstruction as invalid signature.
			return false, nil
		}
		address, err = floutil.NewAddressScriptHash(append([]byte{0, 20}, address.ScriptAddress()...), net)
	case P2WSH:
		// Not Supported, caught higher up
		// return false to be safe
		return false, nil
	}
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in public key
		// reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return address.EncodeAddress() == checkAddress, nil
}

func SignMessage(msg string, coinName string, wif string) (string, error) {
	w, err := floutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}

	return SignMessagePk(msg, coinName, w.PrivKey, w.CompressPubKey)
}

func SignMessagePk(msg string, coinName string, prv *floec.PrivateKey, compressed bool) (string, error) {
	var buf bytes.Buffer
	_ = wire.WriteVarString(&buf, 0, coinName+" Signed Message:\n")
	_ = wire.WriteVarString(&buf, 0, msg)
	messageHash := chainhash.DoubleHashB(buf.Bytes())

	sig, err := floec.SignCompact(floec.S256(), prv, messageHash, compressed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
