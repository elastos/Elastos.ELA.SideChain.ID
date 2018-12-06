package database

import (
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wutil"

	"github.com/elastos/Elastos.ELA.Utility/common"
)

type Database interface {
	AddAddress(address *common.Uint168, script []byte, addrType int) error
	GetAddress(address *common.Uint168) (*wutil.Addr, error)
	GetAddrs() ([]*wutil.Addr, error)
	DeleteAddress(address *common.Uint168) error
	GetAddressUTXOs(address *common.Uint168) ([]*wutil.UTXO, error)
	GetAddressSTXOs(address *common.Uint168) ([]*wutil.STXO, error)
	BestHeight() uint32
	Clear() error
}
