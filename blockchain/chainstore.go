package blockchain

import (
	"bytes"
	"errors"
	"strings"
	"time"

	id "github.com/elastos/Elastos.ELA.SideChain.ID/types"

	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain/database"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
)

const (
	IX_DeactivateCustomizedDID           blockchain.EntryPrefix = 0x89
	IX_VerifiableCredentialExpiresHeight blockchain.EntryPrefix = 0x90
	IX_VerifiableCredentialTXHash        blockchain.EntryPrefix = 0x91
	IX_VerifiableCredentialPayload       blockchain.EntryPrefix = 0x92
	IX_CUSTOMIZEDDIDPayload              blockchain.EntryPrefix = 0x93
	IX_CUSTOMIZEDDIDTXHash               blockchain.EntryPrefix = 0x94
	IX_DIDTXHash                         blockchain.EntryPrefix = 0x95
	IX_DIDPayload                        blockchain.EntryPrefix = 0x96
	IX_DIDExpiresHeight                  blockchain.EntryPrefix = 0x97
	IX_DIDDeactivate                     blockchain.EntryPrefix = 0x98
	IX_CUSTOMIZEDDIDExpiresHeight        blockchain.EntryPrefix = 0x99
)

type IDChainStore struct {
	*blockchain.ChainStore
}

func NewChainStore(genesisBlock *types.Block, dataPath string) (*IDChainStore, error) {
	chainStore, err := blockchain.NewChainStore(dataPath, genesisBlock)
	if err != nil {
		return nil, err
	}

	store := &IDChainStore{
		ChainStore: chainStore,
	}

	store.RegisterFunctions(blockchain.PersistFunction,
		blockchain.StoreFuncNames.PersistTransactions, store.persistTransactions)
	store.RegisterFunctions(blockchain.RollbackFunction,
		blockchain.StoreFuncNames.RollbackTransactions, store.rollbackTransactions)
	return store, nil
}

func (c *IDChainStore) persistTransactions(batch database.Batch, b *types.Block) error {
	for _, txn := range b.Transactions {
		if err := c.PersistTransaction(batch, txn, b.Header.GetHeight()); err != nil {
			return err
		}

		switch txn.TxType {
		case types.RegisterAsset:
			regPayload := txn.Payload.(*types.PayloadRegisterAsset)
			if err := c.PersistAsset(batch, txn.Hash(), regPayload.Asset); err != nil {
				return err
			}
		case types.RechargeToSideChain:
			rechargePayload := txn.Payload.(*types.PayloadRechargeToSideChain)
			hash, err := rechargePayload.GetMainchainTxHash(txn.PayloadVersion)
			if err != nil {
				return err
			}
			c.PersistMainchainTx(batch, *hash)
		case id.RegisterIdentification:
			regPayload := txn.Payload.(*id.PayloadRegisterIdentification)
			for _, content := range regPayload.Contents {
				buf := new(bytes.Buffer)
				buf.WriteString(regPayload.ID)
				buf.WriteString(content.Path)
				if err := c.persistRegisterIdentificationTx(batch,
					buf.Bytes(), txn.Hash()); err != nil {
					return err
				}
			}
		case id.RegisterDID:
			regPayload := txn.Payload.(*id.Operation)

			id := c.GetDIDFromUri(regPayload.PayloadInfo.ID)
			if id == "" {
				return errors.New("invalid regPayload.Doc.ID")
			}
			if err := c.persistRegisterDIDTx(batch, []byte(id),
				txn, b.GetHeight(), b.GetTimeStamp()); err != nil {
				return err
			}
		case id.DeactivateDID:
			deactivateDIDOpt := txn.Payload.(*id.DeactivateDIDOptPayload)
			id := c.GetDIDFromUri(deactivateDIDOpt.Payload)
			if id == "" {
				return errors.New("invalid deactivate DID")
			}
			if err := c.persistDeactivateDIDTx(batch, []byte(id)); err != nil {
				return err
			}
		case id.DeactivateCustomizedDIDTxType:
			deactivateCustomizedDIDPayload := txn.Payload.(*id.DeactivateCustomizedDIDPayload)
			id := deactivateCustomizedDIDPayload.Payload
			if id == "" {
				return errors.New("invalid CustomizedDID ")
			}
			if err := c.persistDeactivateCustomizedDIDTx(batch, []byte(id)); err != nil {
				return err
			}
		case id.CustomizedDID:
			regPayload := txn.Payload.(*id.CustomizedDIDOperation)

			id := regPayload.GetPayloadInfo().CustomID
			if id == "" {
				return errors.New("invalid regPayload.Doc.ID")
			}
			if err := c.persistCustomizedDIDTx(batch, []byte(id),
				txn, b.GetHeight(), b.GetTimeStamp()); err != nil {
				return err
			}
		case id.VerifiableCredentialTxType:
			verifyCredPayload := txn.Payload.(*id.VerifiableCredentialPayload)

			id := verifyCredPayload.Doc.ID
			if id == "" {
				return errors.New("invalid regPayload.Doc.ID")
			}
			if err := c.persistVerifiableCredentialTx(batch, []byte(id),
				txn, b.GetHeight(), b.GetTimeStamp()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *IDChainStore) GetDIDFromUri(idURI string) string {
	index := strings.LastIndex(idURI, ":")
	if index == -1 {
		return ""
	}
	return idURI[index+1:]
}

func (c *IDChainStore) rollbackTransactions(batch database.Batch, b *types.Block) error {
	for _, txn := range b.Transactions {
		if err := c.RollbackTransaction(batch, txn); err != nil {
			return err
		}

		switch txn.TxType {
		case types.RegisterAsset:
			if err := c.RollbackAsset(batch, txn.Hash()); err != nil {
				return err
			}
		case types.RechargeToSideChain:
			rechargePayload := txn.Payload.(*types.PayloadRechargeToSideChain)
			hash, err := rechargePayload.GetMainchainTxHash(txn.PayloadVersion)
			if err != nil {
				return err
			}
			c.RollbackMainchainTx(batch, *hash)
		case id.RegisterIdentification:
			regPayload := txn.Payload.(*id.PayloadRegisterIdentification)
			for _, content := range regPayload.Contents {
				buf := new(bytes.Buffer)
				buf.WriteString(regPayload.ID)
				buf.WriteString(content.Path)
				err := c.rollbackRegisterIdentificationTx(batch, buf.Bytes())
				if err != nil {
					return err
				}
			}
		case id.RegisterDID:
			regPayload := txn.Payload.(*id.Operation)
			id := c.GetDIDFromUri(regPayload.PayloadInfo.ID)
			if id == "" {
				return errors.New("invalid regPayload.Doc.ID")
			}
			if err := c.rollbackRegisterDIDTx(batch, []byte(id), txn); err != nil {
				return err
			}
		case id.CustomizedDID:
			regPayload := txn.Payload.(*id.CustomizedDIDOperation)
			id := regPayload.GetPayloadInfo().CustomID
			if id == "" {
				return errors.New("invalid regPayload.Doc.ID")
			}
			if err := c.rollbackCustomizedDIDTx(batch, []byte(id), txn); err != nil {
				return err
			}
		case id.VerifiableCredentialTxType:
			verifiableCredential := txn.Payload.(*id.VerifiableCredentialPayload)
			id := verifiableCredential.Doc.ID
			if id == "" {
				return errors.New("verifiableCredential.Doc.ID")
			}
			if err := c.rollbackVerifiableCredentialTx(batch, []byte(id), txn); err != nil {
				return err
			}
		case id.DeactivateDID:
			deactivateDID := txn.Payload.(*id.DeactivateDIDOptPayload)
			id := c.GetDIDFromUri(deactivateDID.Payload)
			if id == "" {
				return errors.New("invalid deactivateDID.Payload")
			}
			if err := c.rollbackDeactivateDIDTx(batch, []byte(id), txn); err != nil {
				return err
			}
		case id.DeactivateCustomizedDIDTxType:
			deactivateCustomizedDID := txn.Payload.(*id.DeactivateCustomizedDIDPayload)
			customizeDID := deactivateCustomizedDID.Payload
			if customizeDID == "" {
				return errors.New("invalid deactivateCustomizedDID.Payload")
			}
			if err := c.rollbackDeactivateCustomizedDIDTx(batch, []byte(customizeDID), txn); err != nil {
				return err
			}

		}

	}

	return nil
}

func (c *IDChainStore) persistRegisterIdentificationTx(batch database.Batch,
	idKey []byte, txHash common.Uint256) error {
	key := []byte{byte(blockchain.IX_Identification)}
	key = append(key, idKey...)

	// PUT VALUE
	return batch.Put(key, txHash.Bytes())
}

func (c *IDChainStore) rollbackRegisterIdentificationTx(batch database.Batch,
	idKey []byte) error {
	key := []byte{byte(blockchain.IX_Identification)}
	key = append(key, idKey...)

	// PUT VALUE
	return batch.Delete(key)
}

func (c *IDChainStore) GetRegisterIdentificationTx(idKey []byte) ([]byte, error) {
	key := []byte{byte(blockchain.IX_Identification)}
	data, err := c.Get(append(key, idKey...))
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (c *IDChainStore) TryGetExpiresHeight(Expires string, blockHeight uint32, blockTimeStamp uint32) (uint32, error) {
	expiresTime, err := time.Parse(time.RFC3339, Expires)
	if err != nil {
		return 0, errors.New("invalid Expires")
	}

	var timeSpanSec, expiresSec uint32
	expiresSec = uint32(expiresTime.Unix())
	timeSpanSec = expiresSec - blockTimeStamp

	if expiresSec < blockTimeStamp {
		timeSpanSec = 0
	}
	needsBlocks := timeSpanSec / (2 * 60)
	expiresHeight := blockHeight + needsBlocks
	return expiresHeight, nil
}

func (c *IDChainStore) persistRegisterDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	operation, ok := tx.Payload.(*id.Operation)
	if !ok {
		return errors.New("persistRegisterDIDTx invalid Operation")
	}
	expiresHeight, err := c.TryGetExpiresHeight(operation.PayloadInfo.Expires, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}

	if err := c.persistRegisterDIDExpiresHeight(batch, idKey, expiresHeight); err != nil {
		return err
	}
	if err := c.persistRegisterDIDTxHash(batch, idKey, tx.Hash()); err != nil {
		return err
	}

	if err := c.persistRegisterDIDPayload(batch, tx.Hash(),
		tx.Payload.(*id.Operation)); err != nil {
		return err
	}

	return nil
}

func (c *IDChainStore) PersistVerifiableCredentialTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	return c.persistVerifiableCredentialTx(batch, idKey, tx, blockHeight, blockTimeStamp)
}

//persistVerifiableCredentialTx
func (c *IDChainStore) persistVerifiableCredentialTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	payload := tx.Payload.(*id.VerifiableCredentialPayload)
	verifyCred := payload.Doc.VerifiableCredentialData
	expiresHeight, err := c.TryGetExpiresHeight(verifyCred.ExpirationDate, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}

	if err := c.persistVerifiableCredentialExpiresHeight(batch, idKey, expiresHeight); err != nil {
		return err
	}
	if err := c.persisterifiableCredentialTxHash(batch, idKey, tx.Hash()); err != nil {
		return err
	}
	if err := c.persistVerifiableCredentialPayload(batch, tx.Hash(), payload); err != nil {
		return err
	}

	return nil
}

func (c *IDChainStore) persistDeactivateCustomizedDIDTx(batch database.Batch, idKey []byte) error {
	key := []byte{byte(IX_DeactivateCustomizedDID)}
	key = append(key, idKey...)

	buf := new(bytes.Buffer)
	if err := common.WriteVarUint(buf, 1); err != nil {
		return err
	}
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistCustomizedDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	customizedDIDOperation := tx.Payload.(*id.CustomizedDIDOperation)
	expiresHeight, err := c.TryGetExpiresHeight(customizedDIDOperation.Doc.Expires, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}

	if err := c.persistCustomizedDIDExpiresHeight(batch, idKey, expiresHeight); err != nil {
		return err
	}
	if err := c.persistCustomizedDIDTxHash(batch, idKey, tx.Hash()); err != nil {
		return err
	}

	// todo persit tx type(create and transfer)
	if err := c.persistCustomizedDIDPayload(batch, tx.Hash(), customizedDIDOperation); err != nil {
		return err
	}

	return nil
}

func (c *IDChainStore) PersistCustomizedDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	return c.persistCustomizedDIDTx(batch, idKey, tx, blockHeight, blockTimeStamp)
}

func (c *IDChainStore) PersistRegisterDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction, blockHeight uint32,
	blockTimeStamp uint32) error {
	return c.persistRegisterDIDTx(batch, idKey, tx, blockHeight, blockTimeStamp)
}

func (c *IDChainStore) persistDeactivateDIDTx(batch database.Batch, idKey []byte) error {
	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey...)

	buf := new(bytes.Buffer)
	if err := common.WriteVarUint(buf, 1); err != nil {
		return err
	}
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) PersistDeactivateDIDTx(batch database.Batch, idKey []byte) error {
	return c.persistDeactivateDIDTx(batch, idKey)
}

func (c *IDChainStore) IsDIDDeactivated(did string) bool {
	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey.Bytes()...)

	_, err := c.Get(key)
	if err != nil {
		return false
	}
	return true
}

func (c *IDChainStore) IsCustomizedDIDDeactivated(did string) bool {
	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_DeactivateCustomizedDID)}
	key = append(key, idKey.Bytes()...)

	_, err := c.Get(key)
	if err != nil {
		return false
	}
	return true
}

func (c *IDChainStore) persistVerifiableCredentialPayload(batch database.Batch,
	txHash common.Uint256, p *id.VerifiableCredentialPayload) error {
	key := []byte{byte(IX_VerifiableCredentialPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, id.VerifiableCredentialVersion)
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistVerifiableCredentialExpiresHeight(batch database.Batch,
	idKey []byte, expiresHeight uint32) error {
	key := []byte{byte(IX_VerifiableCredentialExpiresHeight)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := common.WriteUint32(buf, expiresHeight); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := common.WriteUint32(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persisterifiableCredentialTxHash(batch database.Batch,
	idKey []byte, txHash common.Uint256) error {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistRegisterDIDExpiresHeight(batch database.Batch,
	idKey []byte, expiresHeight uint32) error {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := common.WriteUint32(buf, expiresHeight); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := common.WriteUint32(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistCustomizedDIDExpiresHeight(batch database.Batch,
	idKey []byte, expiresHeight uint32) error {
	key := []byte{byte(IX_CUSTOMIZEDDIDExpiresHeight)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := common.WriteUint32(buf, expiresHeight); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := common.WriteUint32(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistRegisterDIDTxHash(batch database.Batch,
	idKey []byte, txHash common.Uint256) error {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistCustomizedDIDTxHash(batch database.Batch,
	idKey []byte, txHash common.Uint256) error {
	key := []byte{byte(IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}

		return batch.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) rollbackCustomizedDIDExpiresHeight(batch database.Batch,
	idKey []byte) error {

	key := []byte{byte(IX_CUSTOMIZEDDIDExpiresHeight)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of expires height
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	if _, err = common.ReadUint32(r); err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}

	// write old expires height
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) rollbackRegisterDIDExpiresHeight(batch database.Batch,
	idKey []byte) error {

	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of expires height
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	if _, err = common.ReadUint32(r); err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}

	// write old expires height
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) rollbackVerifiableCredentialExpiresHeight(batch database.Batch,
	credentialIDKey []byte) error {

	key := []byte{byte(IX_VerifiableCredentialExpiresHeight)}
	key = append(key, credentialIDKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of expires height
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}

	if _, err = common.ReadUint32(r); err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}

	// write old expires height
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return batch.Put(key, buf.Bytes())
}

//rollbackVerifiableCredentialTx
func (c *IDChainStore) rollbackVerifiableCredentialTx(batch database.Batch, credentialIDKey []byte, tx *types.Transaction) error {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, credentialIDKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of tx hashes
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	// get the newest tx hash
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return err
	}
	// if not rollback the newest tx hash return error
	if !txHash.IsEqual(tx.Hash()) {
		return errors.New("not rollback the last one")
	}

	//rollback operation (payload)
	keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)
	batch.Delete(keyPayload)

	//rollback expires height
	err = c.rollbackVerifiableCredentialExpiresHeight(batch, credentialIDKey)
	if err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) rollbackRegisterDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction) error {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of tx hashes
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	// get the newest tx hash
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return err
	}
	// if not rollback the newest tx hash return error
	if !txHash.IsEqual(tx.Hash()) {
		return errors.New("not rollback the last one")
	}

	keyPayload := []byte{byte(IX_DIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)
	batch.Delete(keyPayload)

	//rollback expires height
	err = c.rollbackRegisterDIDExpiresHeight(batch, idKey)
	if err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return batch.Put(key, buf.Bytes())
}

//rollbackCustomizedDIDTx
func (c *IDChainStore) rollbackCustomizedDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction) error {
	key := []byte{byte(IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	// get the count of tx hashes
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("not exist")
	}
	// get the newest tx hash
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return err
	}
	// if not rollback the newest tx hash return error
	if !txHash.IsEqual(tx.Hash()) {
		return errors.New("not rollback the last one")
	}

	keyPayload := []byte{byte(IX_CUSTOMIZEDDIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)
	batch.Delete(keyPayload)

	//rollback expires height
	err = c.rollbackCustomizedDIDExpiresHeight(batch, idKey)
	if err != nil {
		return err
	}

	if count == 1 {
		return batch.Delete(key)
	}

	buf := new(bytes.Buffer)
	// write count
	if err := common.WriteVarUint(buf, count-1); err != nil {
		return err
	}
	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) rollbackDeactivateCustomizedDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction) error {
	key := []byte{byte(IX_DeactivateCustomizedDID)}
	key = append(key, idKey...)
	_, err := c.Get(key)
	if err != nil {
		return err
	}
	batch.Delete(key)
	return nil
}

func (c *IDChainStore) rollbackDeactivateDIDTx(batch database.Batch,
	idKey []byte, tx *types.Transaction) error {
	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey...)

	_, err := c.Get(key)
	if err != nil {
		return err
	}
	batch.Delete(key)
	return nil
}

func (c *IDChainStore) persistCustomizedDIDPayload(batch database.Batch,
	txHash common.Uint256, p *id.CustomizedDIDOperation) error {
	key := []byte{byte(IX_CUSTOMIZEDDIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, id.CustomizedDIDVersion)
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) persistRegisterDIDPayload(batch database.Batch,
	txHash common.Uint256, p *id.Operation) error {
	key := []byte{byte(IX_DIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, id.DIDInfoVersion)
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) GetLastDIDTxData(idKey []byte) (*id.TranasactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	keyPayload := []byte{byte(IX_DIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := c.Get(keyPayload)
	if err != nil {
		return nil, err
	}

	tempOperation := new(id.Operation)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, id.DIDInfoVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"tempOperation Deserialize failed")
	}
	tempTxData := new(id.TranasactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.PayloadInfo.Expires

	return tempTxData, nil
}

func (c *IDChainStore) GetLastCustomizedDIDTxData(idKey []byte) (*id.CustomizedDIDTranasactionData, error) {
	key := []byte{byte(IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	keyPayload := []byte{byte(IX_CUSTOMIZEDDIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := c.Get(keyPayload)
	if err != nil {
		return nil, err
	}

	tempOperation := new(id.CustomizedDIDOperation)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, id.CustomizedDIDVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"CustomizedDIDOperation Deserialize failed")
	}
	tempTxData := new(id.CustomizedDIDTranasactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.GetPayloadInfo().Expires

	return tempTxData, nil
}

func (c *IDChainStore) GetExpiresHeight(idKey []byte) (uint32, error) {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)

	var expiresBlockHeight uint32
	data, err := c.Get(key)
	if err != nil {
		return 0, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("not exist")
	}
	if expiresBlockHeight, err = common.ReadUint32(r); err != nil {
		return 0, err
	}

	return expiresBlockHeight, nil
}
func (c *IDChainStore) GetCustomizedDIDExpiresHeight(idKey []byte) (uint32, error) {
	key := []byte{byte(IX_CUSTOMIZEDDIDExpiresHeight)}
	key = append(key, idKey...)

	var expiresBlockHeight uint32
	data, err := c.Get(key)
	if err != nil {
		return 0, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("not exist")
	}
	if expiresBlockHeight, err = common.ReadUint32(r); err != nil {
		return 0, err
	}

	return expiresBlockHeight, nil
}

func (c *IDChainStore) GetAllDIDTxTxData(idKey []byte) ([]id.TranasactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []id.TranasactionData
	for i := uint64(0); i < count; i++ {
		var txHash common.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		keyPayload := []byte{byte(IX_DIDPayload)}
		keyPayload = append(keyPayload, txHash.Bytes()...)

		payloadData, err := c.Get(keyPayload)
		if err != nil {
			return nil, err
		}
		tempOperation := new(id.Operation)
		r := bytes.NewReader(payloadData)
		err = tempOperation.Deserialize(r, id.DIDInfoVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"payloaddid Deserialize failed")
		}
		tempTxData := new(id.TranasactionData)
		tempTxData.TXID = txHash.String()
		tempTxData.Operation = *tempOperation
		tempTxData.Timestamp = tempOperation.PayloadInfo.Expires
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}

func (c *IDChainStore) GetAllCustomizedDIDTxTxData(idKey []byte) ([]id.CustomizedDIDTranasactionData, error) {
	key := []byte{byte(IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []id.CustomizedDIDTranasactionData
	for i := uint64(0); i < count; i++ {
		var txHash common.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		keyPayload := []byte{byte(IX_DIDPayload)}
		keyPayload = append(keyPayload, txHash.Bytes()...)

		payloadData, err := c.Get(keyPayload)
		if err != nil {
			return nil, err
		}
		tempOperation := new(id.CustomizedDIDOperation)
		r := bytes.NewReader(payloadData)
		err = tempOperation.Deserialize(r, id.CustomizedDIDVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"payloaddid Deserialize failed")
		}
		tempTxData := new(id.CustomizedDIDTranasactionData)
		tempTxData.TXID = txHash.String()
		tempTxData.Operation = *tempOperation
		tempTxData.Timestamp = tempOperation.GetPayloadInfo().Expires
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}

func (c *IDChainStore) GetLastVerifiableCredentialTxData(idKey []byte) (*id.VerifiableCredentialTxData, error) {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := c.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := c.Get(keyPayload)
	if err != nil {
		return nil, err
	}

	credentialPayload := new(id.VerifiableCredentialPayload)
	r = bytes.NewReader(dataPayload)
	err = credentialPayload.Deserialize(r, id.VerifiableCredentialVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"tempOperation Deserialize failed")
	}
	tempTxData := new(id.VerifiableCredentialTxData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *credentialPayload
	tempTxData.Timestamp = credentialPayload.Doc.ExpirationDate

	return tempTxData, nil
}
