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

func CreateAndSignTx(vin []Vin, vout []Vout, keys map[string]*floutil.WIF, net *chaincfg.Params, floData string) (*wire.MsgTx, error) {
	unsignedTx, err := CreateUnsignedTx(vin, vout, floData)
	if err != nil {
		return nil, err
	}

	signedTx, err := SignTx(keys, vin, net, unsignedTx)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

func CreateUnsignedTx(vin []Vin, vout []Vout, floData string) (*wire.MsgTx, error) {
	unsignedTx := wire.NewMsgTx(wire.TxVersion)

	if len(floData) > 0 {
		if unsignedTx.Version < 2 {
			unsignedTx.Version = 2
		}
		unsignedTx.FloData = floData
	}

	for i := range vin {
		op := wire.NewOutPoint(vin[i].Hash, vin[i].Index)
		txIn := wire.NewTxIn(op, nil, nil)
		unsignedTx.AddTxIn(txIn)
	}

	for i := range vout {
		script, err := txscript.PayToAddrScript(vout[i].Addr)
		if err != nil {
			return nil, err
		}
		txOut := wire.NewTxOut(int64(vout[i].Amount), script)
		unsignedTx.AddTxOut(txOut)
	}

	return unsignedTx, nil
}

func SignTx(keys map[string]*floutil.WIF, vin []Vin, net *chaincfg.Params, unsignedTx *wire.MsgTx) (*wire.MsgTx, error) {
	lookupKey := func(a floutil.Address) (*floec.PrivateKey, bool, error) {
		wif, ok := keys[a.EncodeAddress()]
		if !ok {
			return nil, false, errors.New("no key for address")
		}
		return wif.PrivKey, wif.CompressPubKey, nil
	}
	for i := range vin {
		sigScript, err := txscript.SignTxOutput(net,
			unsignedTx, i, vin[i].PkScript, txscript.SigHashAll,
			txscript.KeyClosure(lookupKey), nil, nil)
		if err != nil {
			return nil, err
		}
		unsignedTx.TxIn[i].SignatureScript = sigScript
	}
	return unsignedTx, nil
}
