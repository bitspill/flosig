package flosig

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/floec"
	"github.com/bitspill/flod/txscript"
	"github.com/bitspill/flod/wire"
	"github.com/bitspill/floutil"
)

func TestCreateAndSignTx(t *testing.T) {
	// Test case adapted from btcsuite example
	// https://github.com/btcsuite/btcd/blob/98cae74/txscript/example_test.go#L83

	// Ordinarily the private key would come from whatever storage mechanism
	// is being used, but for this example just hard code it.
	privKeyBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2" +
		"d4f8720ee63e502ee2869afab7de234b80c")
	if err != nil {
		t.Fatal(err)
	}
	privKey, pubKey := floec.PrivKeyFromBytes(floec.S256(), privKeyBytes)
	pubKeyHash := floutil.Hash160(pubKey.SerializeCompressed())
	addr, err := floutil.NewAddressPubKeyHash(pubKeyHash,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}

	// For this example, create a fake transaction that represents what
	// would ordinarily be the real transaction that is being spent.  It
	// contains a single output that pays to address in the amount of 1 BTC.
	originTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	txIn := wire.NewTxIn(prevOut, []byte{txscript.OP_0, txscript.OP_0}, nil)
	originTx.AddTxIn(txIn)
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	txOut := wire.NewTxOut(100000000, pkScript)
	originTx.AddTxOut(txOut)
	originTxHash := originTx.TxHash()

	vin := []Vin{{
		Hash:     &originTxHash,
		Index:    0,
		PkScript: pkScript,
	}}
	vout := []Vout{{
		Addr:   addr,
		Amount: 100000000,
	}}

	wif, err := floutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*floutil.WIF{
		addr.EncodeAddress(): wif,
	}

	redeemTx, err := CreateAndSignTx(vin, vout, keys, &chaincfg.MainNetParams, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}

	// Prove that the transaction has been validly signed by executing the
	// script pair.
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig |
		txscript.ScriptDiscourageUpgradableNops
	for i := range originTx.TxOut {
		vm, err := txscript.NewEngine(originTx.TxOut[i].PkScript, redeemTx, 0,
			flags, nil, nil, -1)
		if err != nil {
			t.Fatal(err)
		}
		if err := vm.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("Transaction successfully signed")
}
