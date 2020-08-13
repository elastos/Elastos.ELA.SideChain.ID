package blockchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	id "github.com/elastos/Elastos.ELA.SideChain.ID/types"

	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain/database"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	IX_DIDTXHash        blockchain.EntryPrefix = 0x95
	IX_DIDPayload       blockchain.EntryPrefix = 0x96
	IX_DIDExpiresHeight blockchain.EntryPrefix = 0x97
)

type IDChainStore struct {
	*blockchain.ChainStore

	mongoDB *mongo.Client
}

func NewChainStore(genesisBlock *types.Block, dataPath string, mongoDB *mongo.Client) (*IDChainStore, error) {
	chainStore, err := blockchain.NewChainStore(dataPath, genesisBlock)
	if err != nil {
		return nil, err
	}

	store := &IDChainStore{
		ChainStore: chainStore,
		mongoDB:    mongoDB,
	}
	if err := store.initChainStoreWithMongoDB(); err != nil {
		return nil, err
	}

	store.RegisterFunctions(blockchain.PersistFunction,
		blockchain.StoreFuncNames.PersistTransactions, store.persistTransactions)
	store.RegisterFunctions(blockchain.PersistCallbackFunction,
		blockchain.StoreFuncNames.PersistTransactions, store.callbackAfterPersistTransactions)
	store.RegisterFunctions(blockchain.RollbackFunction,
		blockchain.StoreFuncNames.RollbackTransactions, store.rollbackTransactions)
	store.RegisterFunctions(blockchain.RollbackCallbackFunction,
		blockchain.StoreFuncNames.RollbackTransactions, store.callbackAfterRollbackTransactions)
	return store, nil
}

func (c *IDChainStore) initChainStoreWithMongoDB() (err error) {
	if c.mongoDB == nil {
		return nil
	}
	// record current block height
	db := c.mongoDB.Database("did_db")
	collection := db.Collection("did_collection_height")
	var count int64
	if count, err = collection.CountDocuments(context.Background(), bson.M{}); err != nil {
		return
	}
	currentHeight := c.GetHeight()

	if count == 0 {
		payload := bson.M{"Height": 0}
		var result *mongo.InsertOneResult
		if result, err = collection.InsertOne(context.Background(), payload); err != nil {
			return err
		}
		fmt.Println(result)

		return c.initMongoDBData(uint32(1), currentHeight)
	}

	// get current height
	result := collection.FindOne(context.Background(), bson.D{{}})
	type heightCollection struct {
		Height uint32
	}
	var heightC heightCollection
	if err = result.Decode(&heightC); err != nil {
		return
	}

	return c.initMongoDBData(heightC.Height, currentHeight)
}

func (c *IDChainStore) initMongoDBData(startHeight, endHeight uint32) error {
	for i := startHeight; i <= endHeight; i++ {
		blockHash, err := c.GetBlockHash(i)
		if err != nil {
			return err
		}
		block, err := c.GetBlock(blockHash)
		if err != nil {
			return err
		}

		if err := c.callbackAfterPersistTransactions(nil, block); err != nil {
			return err
		}
	}

	return nil
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
				return errors.New("invalid regPayload.PayloadInfo.ID")
			}
			if err := c.persistRegisterDIDTx(batch, []byte(id),
				txn, b.GetHeight(), b.GetTimeStamp()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *IDChainStore) persistHeightWithMongoDB(session mongo.Session, height uint32) (err error) {
	// persist current height
	if err = mongo.WithSession(context.Background(), session, func(sc mongo.SessionContext) error {
		db := c.mongoDB.Database("did_db")
		collection := db.Collection("did_collection_height")

		filter := bson.M{"Height": height - 1}
		update := bson.M{"$set": bson.M{"Height": height}}
		if _, err = collection.UpdateOne(context.Background(), filter, update); err != nil {
			return err
		}
		fmt.Println("current height:", height)
		return nil
	}); err != nil {
		panic(err)
	}
	return nil
}

func (c *IDChainStore) startSessionWithMongoDB() (mongo.Session, error) {
	var session mongo.Session
	var err error
	if session, err = c.mongoDB.StartSession(); err != nil {
		panic(err)
	}
	if err = session.StartTransaction(); err != nil {
		panic(err)
	}
	return session, nil
}

func (c *IDChainStore) endSessionWithMongoDB(session mongo.Session) {
	// end session
	if err := session.CommitTransaction(context.Background()); err != nil {
		panic(err)
	}
	session.EndSession(context.Background())
}

func (c *IDChainStore) callbackAfterPersistTransactions(batch database.Batch, b *types.Block) error {
	session, err := c.startSessionWithMongoDB()
	if err != nil {
		return err
	}
	for _, txn := range b.Transactions {
		switch txn.TxType {
		case id.RegisterIdentification:
			// no need to process?
		case id.RegisterDID:
			regPayload := txn.Payload.(*id.Operation)
			if c.mongoDB != nil {
				if err := c.persistRegisterDIDTransactionWithMongoDB(session,
					regPayload, b.GetHeight(), b.GetTimeStamp(), txn.Hash()); err != nil {
					return err
				}
			}
		}
	}
	c.persistHeightWithMongoDB(session, b.GetHeight())
	c.endSessionWithMongoDB(session)
	return nil
}

func (c *IDChainStore) persistRegisterDIDTransactionWithMongoDB(session mongo.Session, payload *id.Operation,
	height uint32, timeStamp uint32, txHash common.Uint256) (err error) {

	didPayload := &id.DIDTransactionInfo{
		TXID:        txHash.String(),
		Timestamp:   timeStamp,
		BlockHeight: height,
		Header:      payload.Header,
		Payload:     payload.Payload,
		PayloadInfo: payload.PayloadInfo,
		Proof:       payload.Proof,
	}

	// persist transaction payload
	if err = mongo.WithSession(context.Background(), session, func(sc mongo.SessionContext) error {
		db := c.mongoDB.Database("did_db")
		collection := db.Collection("did_collection")

		var result *mongo.InsertOneResult
		if result, err = collection.InsertOne(context.Background(), didPayload); err != nil {
			return err
		}
		fmt.Println(result)

		return nil
	}); err != nil {
		panic(err)
	}
	return
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
				return errors.New("invalid regPayload.PayloadInfo.ID")
			}
			if err := c.rollbackRegisterDIDTx(batch, []byte(id), txn); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *IDChainStore) callbackAfterRollbackTransactions(batch database.Batch, b *types.Block) error {
	for _, txn := range b.Transactions {
		switch txn.TxType {
		case id.RegisterIdentification:
		case id.RegisterDID:
			regPayload := txn.Payload.(*id.Operation)
			if c.mongoDB != nil {
				if err := c.rollbackRegisterDIDTransactionWithMongoDB(
					regPayload, b.GetHeight()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func Del(collection *mongo.Collection, m bson.M) {
	deleteResult, err := collection.DeleteOne(context.Background(), m)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("collection.DeleteOne:", deleteResult)
}

func (c *IDChainStore) rollbackRegisterDIDTransactionWithMongoDB(
	payload *id.Operation, height uint32) (err error) {
	var session mongo.Session
	if session, err = c.mongoDB.StartSession(); err != nil {
		panic(err)
	}
	if err = session.StartTransaction(); err != nil {
		panic(err)
	}

	// rollback transaction payload
	if err = mongo.WithSession(context.TODO(), session, func(sc mongo.SessionContext) error {
		db := c.mongoDB.Database("did_db")
		collection := db.Collection("did_collection")

		var result *mongo.DeleteResult
		if result, err = collection.DeleteOne(context.Background(), payload); err != nil {
			return err
		}
		fmt.Println(result)

		if err = session.CommitTransaction(sc); err != nil {
			panic(err)
		}
		return nil
	}); err != nil {
		panic(err)
	}

	// rollback current height
	if err = mongo.WithSession(context.TODO(), session, func(sc mongo.SessionContext) error {
		db := c.mongoDB.Database("did_db")
		collection := db.Collection("did_collection_height")

		filter := bson.M{"Height": height}
		update := bson.M{"$set": bson.M{"Height": height - 1}}
		var result *mongo.UpdateResult
		if result, err = collection.UpdateOne(context.TODO(), filter, update); err != nil {
			return err
		}
		fmt.Println(result)
		if err = session.CommitTransaction(sc); err != nil {
			panic(err)
		}
		return nil
	}); err != nil {
		panic(err)
	}

	// end session
	session.EndSession(context.TODO())
	return
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

func (c *IDChainStore) TryGetExpiresHeight(txn *types.Transaction,
	blockHeight uint32,
	blockTimeStamp uint32) (uint32, error) {
	payloadDidInfo, ok := txn.Payload.(*id.Operation)
	if !ok {
		return 0, errors.New("invalid Operation")
	}
	if payloadDidInfo.PayloadInfo == nil {
		return 0, errors.New("invalid PayloadInfo")
	}

	expiresTime, err := time.Parse(time.RFC3339, payloadDidInfo.PayloadInfo.Expires)
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

	expiresHeight, err := c.TryGetExpiresHeight(tx, blockHeight, blockTimeStamp)
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

func (c *IDChainStore) persistRegisterDIDPayload(batch database.Batch,
	txHash common.Uint256, p *id.Operation) error {
	key := []byte{byte(IX_DIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, id.DIDInfoVersion)
	return batch.Put(key, buf.Bytes())
}

func (c *IDChainStore) GetLastDIDTxData(idKey []byte) (*id.TransactionData, error) {
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
	tempTxData := new(id.TransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.PayloadInfo.Expires

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

func (c *IDChainStore) GetAllDIDTxTxData(idKey []byte) ([]id.TransactionData, error) {
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
	var transactionsData []id.TransactionData
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
		tempTxData := new(id.TransactionData)
		tempTxData.TXID = txHash.String()
		tempTxData.Operation = *tempOperation
		tempTxData.Timestamp = tempOperation.PayloadInfo.Expires
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}
