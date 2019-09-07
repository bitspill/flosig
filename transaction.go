package flosig

import (
	"errors"

	"github.com/bitspill/flod/chaincfg"
	"github.com/bitspill/flod/chaincfg/chainhash"
	"github.com/bitspill/flod/floec"
	"github.com/bitspill/flod/txscript"
	"github.com/bitspill/flod/wire"
	"github.com/bitspill/floutil"
)

type Vin struct {
	Hash     *chainhash.Hash
	Index    uint32
	PkScript []byte
}

type Vout struct {
	Addr   floutil.Address
	Amount floutil.Amount
}

func CreateAndSignTx(vin []Vin, vout []Vout, keys map[string]*floutil.WIF, net *chaincfg.Params) (*wire.MsgTx, error) {
	outputTx := wire.NewMsgTx(wire.TxVersion)

	for i := range vin {
		op := wire.NewOutPoint(vin[i].Hash, vin[i].Index)
		txIn := wire.NewTxIn(op, nil, nil)
		outputTx.AddTxIn(txIn)
	}

	for i := range vout {
		script, err := txscript.PayToAddrScript(vout[i].Addr)
		if err != nil {
			return nil, err
		}
		txOut := wire.NewTxOut(int64(vout[i].Amount), script)
		outputTx.AddTxOut(txOut)
	}

	lookupKey := func(a floutil.Address) (*floec.PrivateKey, bool, error) {
		wif, ok := keys[a.EncodeAddress()]
		if !ok {
			return nil, false, errors.New("no key for address")
		}
		return wif.PrivKey, wif.CompressPubKey, nil
	}

	for i := range vin {
		sigScript, err := txscript.SignTxOutput(net,
			outputTx, i, vin[i].PkScript, txscript.SigHashAll,
			txscript.KeyClosure(lookupKey), nil, nil)
		if err != nil {
			return nil, err
		}
		outputTx.TxIn[i].SignatureScript = sigScript
	}

	return outputTx, nil
}
