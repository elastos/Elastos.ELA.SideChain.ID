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
const SlotCustomizedDID = "customizeddid"
const SlotVerifiableCredential = "verifiablecredential"
const SlotDeactivateCustomizedDID = "deactivatecustomizeddid"

func New(cfg *memp.Config) *memp.TxPool {
	txPool := memp.New(cfg)
	txPool.AddConflictSlot(&memp.Conflict{
		Name: SlotRegisterDID,
		Slot: memp.NewConflictSlot(memp.Str,
			memp.KeyTypeFuncPair{
				Type: types.DIDOperation,
				Func: checkDIDTransaction,
			},
		),
	})
	return txPool
}

func checkDIDTransaction(chain *blockchain.BlockChain, tx *sctype.Transaction) (interface{}, error) {
	p, ok := tx.Payload.(*types.DIDPayload)
	if !ok {
		return nil, errors.New("convert the payload of register did tx failed")
	}

	switch p.Header.Operation {
	case types.Create_DID_Operation, types.Update_DID_Operation, types.Transfer_DID_Operation:
		return p.DIDDoc.ID, nil

	case types.Deactivate_DID_Operation:
		var did string
		if types.IsURIHasPrefix(p.Payload) {
			did = types.GetDIDFromUri(p.Payload)
		} else {
			did = p.Payload
		}
		return did, nil

	case types.Declare_Verifiable_Credential_Operation, types.Revoke_Verifiable_Credential_Operation:
		return p.CredentialDoc.ID, nil
	}

	return nil, errors.New("invalid operation")
}
