package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/store/headers"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/store/sqlite"
	"github.com/elastos/Elastos.ELA.SideChain.ID/wallet/wutil"

	"github.com/elastos/Elastos.ELA.SPV/database"
	"github.com/elastos/Elastos.ELA.SPV/sdk"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA.Utility/common"
	"github.com/elastos/Elastos.ELA.Utility/http/jsonrpc"
	httputil "github.com/elastos/Elastos.ELA.Utility/http/util"
	"github.com/elastos/Elastos.ELA.Utility/signal"
)

const (
	MaxPeers = 12
)

var ErrInvalidParameter = fmt.Errorf("invalide parameter")

type didwallet struct {
	sdk.IService
	db     sqlite.DataStore
	filter *sdk.AddrFilter
}

// Batch returns a TxBatch instance for transactions batch
// commit, this can get better performance when commit a bunch
// of transactions within a block.
func (w *didwallet) Batch() database.TxBatch {
	return &txBatch{
		db:     w.db,
		batch:  w.db.Batch(),
		filter: w.getAddrFilter(),
	}
}

// HaveTx returns if the transaction already saved in database
// by it's id.
func (w *didwallet) HaveTx(txId *common.Uint256) (bool, error) {
	tx, err := w.db.Txs().Get(txId)
	return tx != nil, err
}

// GetTxs returns all transactions within the given height.
func (w *didwallet) GetTxs(height uint32) ([]*util.Tx, error) {
	return nil, nil
}

// RemoveTxs delete all transactions on the given height.  Return
// how many transactions are deleted from database.
func (w *didwallet) RemoveTxs(height uint32) (int, error) {
	batch := w.db.Batch()
	err := batch.RollbackHeight(height)
	if err != nil {
		return 0, batch.Rollback()
	}
	return 0, batch.Commit()
}

// Clear delete all data in database.
func (w *didwallet) Clear() error {
	return w.db.Clear()
}

// Close database.
func (w *didwallet) Close() error {
	return w.db.Close()
}

func (w *didwallet) GetFilterData() ([]*common.Uint168, []*util.OutPoint) {
	utxos, err := w.db.UTXOs().GetAll()
	if err != nil {
		swaltlog.Debugf("GetAll UTXOs error: %v", err)
	}
	stxos, err := w.db.STXOs().GetAll()
	if err != nil {
		swaltlog.Debugf("GetAll STXOs error: %v", err)
	}
	outpoints := make([]*util.OutPoint, 0, len(utxos)+len(stxos))
	for _, utxo := range utxos {
		outpoints = append(outpoints, utxo.Op)
	}
	for _, stxo := range stxos {
		outpoints = append(outpoints, stxo.Op)
	}

	return w.getAddrFilter().GetAddrs(), outpoints
}

func (w *didwallet) NotifyNewAddress(hash []byte) {
	// Reload address filter to include new address
	w.loadAddrFilter()
	// Broadcast filterload message to connected peers
	w.UpdateFilter()
}

func (w *didwallet) getAddrFilter() *sdk.AddrFilter {
	if w.filter == nil {
		w.loadAddrFilter()
	}
	return w.filter
}

func (w *didwallet) loadAddrFilter() *sdk.AddrFilter {
	addrs, _ := w.db.Addrs().GetAll()
	w.filter = sdk.NewAddrFilter(nil)
	for _, addr := range addrs {
		w.filter.AddAddr(addr.Hash())
	}
	return w.filter
}

// TransactionAnnounce will be invoked when received a new announced transaction.
func (w *didwallet) TransactionAnnounce(tx util.Transaction) {
	// TODO
}

// TransactionAccepted will be invoked after a transaction sent by
// SendTransaction() method has been accepted.  Notice: this method needs at
// lest two connected peers to work.
func (w *didwallet) TransactionAccepted(tx util.Transaction) {
	// TODO
}

// TransactionRejected will be invoked if a transaction sent by SendTransaction()
// method has been rejected.
func (w *didwallet) TransactionRejected(tx util.Transaction) {
	// TODO
}

// TransactionConfirmed will be invoked after a transaction sent by
// SendTransaction() method has been packed into a block.
func (w *didwallet) TransactionConfirmed(tx *util.Tx) {
	// TODO
}

// BlockCommitted will be invoked when a block and transactions within it are
// successfully committed into database.
func (w *didwallet) BlockCommitted(block *util.Block) {
	if !w.IsCurrent() {
		return
	}

	w.db.State().PutHeight(block.Height)
	// TODO
}

type txBatch struct {
	db     sqlite.DataStore
	batch  sqlite.DataBatch
	filter *sdk.AddrFilter
}

// PutTx add a store transaction operation into batch, and return
// if it is a false positive and error.
func (b *txBatch) PutTx(mtx util.Transaction, height uint32) (bool, error) {
	tx := mtx.(*wutil.Tx)
	txId := tx.Hash()
	hits := 0

	// Check if any UTXOs within this wallet have been spent.
	for _, input := range tx.Inputs {
		op := util.NewOutPoint(input.Previous.TxID, input.Previous.Index)
		utxo, _ := b.db.UTXOs().Get(op)

		// Skip if no match.
		if utxo == nil {
			continue
		}

		// Delete used UTXO.
		err := b.batch.UTXOs().Del(op)
		if err != nil {
			return false, err
		}

		// Put into STXO.
		err = b.batch.STXOs().Put(wutil.NewSTXO(utxo, height, txId))
		if err != nil {
			return false, err
		}

		// increase hits.
		hits++
	}

	// Check if there are any output to this wallet address.
	for index, output := range tx.Outputs {
		// Filter address
		if b.filter.ContainAddr(output.ProgramHash) {
			var lockTime = output.OutputLock
			if tx.TxType == types.CoinBase {
				lockTime = height + 100
			}
			utxo := wutil.NewUTXO(txId, height, index, output.Value, lockTime, output.ProgramHash)
			err := b.batch.UTXOs().Put(utxo)
			if err != nil {
				return false, err
			}
			hits++
		}
	}

	// If no hits, no need to save transaction
	if hits == 0 {
		return true, nil
	}

	// Save transaction
	err := b.batch.Txs().Put(util.NewTx(tx, height))
	if err != nil {
		return false, err
	}

	return false, nil
}

// DelTx add a delete transaction operation into batch.
func (b *txBatch) DelTx(txId *common.Uint256) error {
	return b.batch.Txs().Del(txId)
}

// DelTxs add a delete transactions on given height operation.
func (b *txBatch) DelTxs(height uint32) error {
	// Delete transactions is used when blockchain doing rollback, this not
	// only delete the transactions on the given height, and also restore
	// STXOs and remove UTXOs within these transactions.
	return b.batch.RollbackHeight(height)
}

// Rollback cancel all operations in current batch.
func (b *txBatch) Rollback() error {
	return b.batch.Rollback()
}

// Commit the added transactions into database.
func (b *txBatch) Commit() error {
	return b.batch.Commit()
}

// Functions for RPC service.
func (w *didwallet) notifyNewAddress(params httputil.Params) (interface{}, error) {
	addrStr, ok := params.String("addr")
	if !ok {
		return nil, ErrInvalidParameter
	}

	address, err := common.Uint168FromAddress(addrStr)
	if err != nil {
		return nil, err
	}

	swaltlog.Debugf("receive notifyNewAddress %s", address)

	// Reload address filter to include new address
	w.loadAddrFilter()

	// Broadcast filterload message to connected peers
	w.UpdateFilter()

	return nil, nil
}

func (w *didwallet) sendTransaction(params httputil.Params) (interface{}, error) {
	data, ok := params.String("data")
	if !ok {
		return nil, ErrInvalidParameter
	}

	txBytes, err := hex.DecodeString(data)
	if err != nil {
		return nil, ErrInvalidParameter
	}

	var tx = newTransaction()
	err = tx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		return nil, fmt.Errorf("deserialize transaction failed %s", err)
	}

	return nil, w.SendTransaction(tx)
}

func NewWallet() (*didwallet, error) {
	// Initialize headers db
	headers, err := headers.NewDatabase(didWalletDataDir)
	if err != nil {
		return nil, err
	}

	db, err := sqlite.NewDatabase(didWalletDataDir)
	if err != nil {
		return nil, err
	}

	w := didwallet{
		db: db,
	}
	chainStore := database.NewDefaultChainDB(headers, &w)

	// Initialize spv service
	w.IService, err = sdk.NewService(
		&sdk.Config{
			DataDir:        didWalletDataDir,
			Magic:          activeNetParams.Magic,
			SeedList:       []string{"localhost"},
			DefaultPort:    activeNetParams.DefaultPort,
			MaxPeers:       MaxPeers,
			GenesisHeader:  GenesisHeader(),
			ChainStore:     chainStore,
			NewTransaction: newTransaction,
			NewBlockHeader: wutil.NewEmptyHeader,
			GetFilterData:  w.GetFilterData,
			StateNotifier:  &w,
		})
	if err != nil {
		return nil, err
	}

	s := jsonrpc.NewServer(&jsonrpc.Config{
		Path:      "/wallet",
		ServePort: cfg.HttpJsonPort + 33,
	})
	s.RegisterAction("notifynewaddress", w.notifyNewAddress, "addr")
	s.RegisterAction("sendrawtransaction", w.sendTransaction, "data")

	errChan := make(chan error)
	go func() {
		if err := s.Start(); err != nil {
			errChan <- err
		}
	}()
	select {
	case err := <-errChan:
		return nil, err
	case <-time.After(time.Millisecond * 100):
	}

	return &w, nil
}

func newTransaction() util.Transaction {
	return wutil.NewTx(&types.Transaction{})
}

// GenesisHeader creates a specific genesis header by the given
// foundation address.
func GenesisHeader() util.BlockHeader {
	return wutil.NewHeader(&activeNetParams.GenesisBlock.Header)
}

func main() {
	swaltlog.Infof("Version: %s", Version)

	// Listen interrupt signals.
	interrupt := signal.NewInterrupt()

	// Create the SPV wallet instance.
	w, err := NewWallet()
	if err != nil {
		swaltlog.Error("Initiate SPV service failed,", err)
		os.Exit(0)
	}
	defer w.Stop()

	w.Start()

	<-interrupt.C
}
