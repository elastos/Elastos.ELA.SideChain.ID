package mempool

import (
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ID/types"
	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	memp "github.com/elastos/Elastos.ELA.SideChain/mempool"
	sctype "github.com/elastos/Elastos.ELA.SideChain/types"
)

const SlotRegisterDID = "registerdid"
const SlotDeactivateDID = "deactivatedid"

func New(cfg *memp.Config) *memp.TxPool {
	txPool := memp.New(cfg)
	txPool.AddConflictSlot(&memp.Conflict{
		Name: SlotRegisterDID,
		Slot: memp.NewConflictSlot(memp.Str,
			memp.KeyTypeFuncPair{
				Type: types.RegisterDID,
				Func: addRegisterDIDTransactionHash,
			},
		),
	})
	txPool.AddConflictSlot(&memp.Conflict{
		Name: SlotDeactivateDID,
		Slot: memp.NewConflictSlot(memp.Str,
			memp.KeyTypeFuncPair{
				Type: types.DeactivateDID,
				Func: addDeactivateDIDTransactionHash,
			},
		),
	})
	return txPool
}

func addRegisterDIDTransactionHash(
	chain *blockchain.BlockChain, tx *sctype.Transaction) (interface{}, error) {
	regPayload, ok := tx.Payload.(*types.Operation)
	if !ok {
		return nil, errors.New("convert the payload of register did tx failed")
	}
	return regPayload.PayloadInfo.ID, nil
}

//
func addDeactivateDIDTransactionHash(
	chain *blockchain.BlockChain, tx *sctype.Transaction) (interface{}, error) {
	deactivateDIDPayload, ok := tx.Payload.(*types.DeactivateDIDOptPayload)
	if !ok {
		return nil, errors.New("convert the payload of DeactivateDIDOpt tx failed")
	}
	var did string
	if types.IsURIHasPrefix(deactivateDIDPayload.Payload) {
		did = types.GetDIDFromUri(deactivateDIDPayload.Payload)
	} else {
		did = deactivateDIDPayload.Payload
	}
	return did, nil
}
