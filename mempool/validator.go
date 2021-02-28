package mempool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/elastos/Elastos.ELA.SideChain.ID/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain.ID/pact"
	"github.com/elastos/Elastos.ELA.SideChain.ID/params"
	id "github.com/elastos/Elastos.ELA.SideChain.ID/types"
	"github.com/elastos/Elastos.ELA.SideChain.ID/types/base64url"
	"github.com/elastos/Elastos.ELA.SideChain/mempool"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/spv"
	"github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA.SideChain/vm"
	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/crypto"
)

const (
	CheckDIDFuncName                     = "checkregisterdid"
	CheckUpdateDIDFuncName               = "checkupdatedid"
	CheckDeactivateDIDFuncName           = "checkdeactivatedid"
	CheckCustomizedDIDFuncName           = "checkcustomizeddid"
	CheckVerifiableCredentialFuncName    = "checkverifiablecredential"
	CheckDeactivateCustomizedDIDFuncName = "checkdeactivatecustomizeddid"
)
const PrefixCRDID contract.PrefixType = 0x67

func CreateCRDIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

type validator struct {
	*mempool.Validator
	didParam      *params.DIDParams
	systemAssetID common.Uint256
	foundation    common.Uint168
	spvService    *spv.Service
	Store         *blockchain.IDChainStore
}

func NewValidator(cfg *mempool.Config, store *blockchain.IDChainStore, didParams *params.DIDParams) *validator {
	var val validator
	val.Validator = mempool.NewValidator(cfg)
	val.didParam = didParams
	val.systemAssetID = cfg.ChainParams.ElaAssetId
	val.foundation = cfg.ChainParams.Foundation
	val.spvService = cfg.SpvService
	val.Store = store
	val.RegisterSanityFunc(mempool.FuncNames.CheckTransactionOutput, val.checkTransactionOutput)
	val.RegisterSanityFunc(mempool.FuncNames.CheckTransactionPayload, val.checkTransactionPayload)

	val.RegisterContextFunc(mempool.FuncNames.CheckTransactionSignature, val.checkTransactionSignature)
	val.RegisterContextFunc(CheckDIDFuncName, val.checkDIDTransaction)
	//val.RegisterContextFunc(CheckDeactivateDIDFuncName, val.checkDeactivateDID)
	//val.RegisterContextFunc(CheckCustomizedDIDFuncName, val.checkCustomizedDID)
	//val.RegisterContextFunc(CheckVerifiableCredentialFuncName, val.checkVerifiableCredential)
	//val.RegisterContextFunc(CheckDeactivateCustomizedDIDFuncName, val.checkCustomizedDIDDeactivateTX)

	return &val
}

func (v *validator) checkTransactionPayload(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	switch pld := txn.Payload.(type) {
	case *types.PayloadRegisterAsset:
		if pld.Asset.Precision < types.MinPrecision || pld.Asset.Precision > types.MaxPrecision {
			return errors.New("[ID CheckTransactionPayload] Invalide asset Precision.")
		}
		if !checkAmountPrecise(pld.Amount, pld.Asset.Precision, types.MaxPrecision) {
			return errors.New("[ID CheckTransactionPayload] Invalide asset value,out of precise.")
		}
	case *types.PayloadTransferAsset:
	case *types.PayloadRecord:
	case *types.PayloadCoinBase:
	case *types.PayloadRechargeToSideChain:
	case *types.PayloadTransferCrossChainAsset:
	case *id.PayloadRegisterIdentification:
	case *id.DIDPayload:
	default:
		return errors.New("[ID CheckTransactionPayload] [txValidator],invalidate transaction payload type.")
	}
	return nil
}

func checkAmountPrecise(amount common.Fixed64, precision byte, assetPrecision byte) bool {
	return amount.IntValue()%int64(math.Pow10(int(assetPrecision-precision))) == 0
}

func (v *validator) checkTransactionOutput(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	if len(txn.Outputs) < 1 {
		return errors.New("[checkTransactionOutput] transaction has no outputs")
	}

	// check if output address is valid
	for _, output := range txn.Outputs {
		if output.AssetID != v.systemAssetID {
			return errors.New("[checkTransactionOutput] asset ID in output is invalid")
		}

		if !checkOutputProgramHash(output.ProgramHash) {
			return errors.New("[checkTransactionOutput] output address is invalid")
		}
	}

	return nil
}

func checkOutputProgramHash(programHash common.Uint168) bool {
	switch contract.PrefixType(programHash[0]) {
	case contract.PrefixStandard, contract.PrefixMultiSig, contract.PrefixCrossChain,
		pact.PrefixRegisterId:
		return true
	}
	var empty = common.Uint168{}
	if programHash == empty {
		return true
	}
	return false
}

func (v *validator) checkTransactionSignature(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	if txn.IsRechargeToSideChainTx() {
		if err := v.spvService.VerifyTransaction(txn); err != nil {
			return errors.New("[ID checkTransactionSignature] Invalide recharge to side chain tx: " + err.Error())
		}
		return nil
	}

	hashes, err := v.TxProgramHashes(txn)
	if err != nil {
		return errors.New("[ID checkTransactionSignature] Get program hashes error:" + err.Error())
	}

	// Add ID program hash to hashes
	if id.IsRegisterIdentificationTx(txn) {
		for _, output := range txn.Outputs {
			if output.ProgramHash[0] == pact.PrefixRegisterId {
				hashes = append(hashes, output.ProgramHash)
				break
			}
		}
	}

	// Sort first
	common.SortProgramHashByCodeHash(hashes)
	if err := mempool.SortPrograms(txn.Programs); err != nil {
		return errors.New("[ID checkTransactionSignature] Sort program hashes error:" + err.Error())
	}

	err = mempool.RunPrograms(txn, hashes, txn.Programs)
	if err != nil {
		return errors.New("[ID checkTransactionSignature] Run program error:" + err.Error())
	}

	return nil
}

func getUriSegment(uri string) string {
	index := strings.LastIndex(uri, "#")
	if index == -1 {
		return ""
	}
	return uri[index:]
}

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func (v *validator) checkVerificationMethodV0(proof *id.Proof,
	DIDDoc *id.DIDDoc) error {
	proofUriSegment := getUriSegment(proof.VerificationMethod)
	for _, auth := range DIDDoc.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				return nil
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(id.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return nil
			}
		default:
			return errors.New("[ID checkVerificationMethodV0] invalid  auth.(type)")
		}
	}
	//if not in Authentication
	//VerificationMethod uri -------->to find publicKeyBase58 in publicKey array which id is
	//VerificationMethod uri and publicKeyBase58 can derive id address
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		//get PublicKeyBase58 accord to VerificationMethod
		if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getCIDAdress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress == v.Store.GetDIDFromUri(DIDDoc.ID) {
				return nil
			}
		}
	}
	return errors.New("[ID checkVerificationMethodV0] wrong public key by VerificationMethod ")
}

func GetDIDAndCompactSymbolFromUri(idURI string) (string, string) {
	index := strings.LastIndex(idURI, "#")
	if index == -1 {
		return "", ""
	}
	return idURI[:index], idURI[index:]
}

func IsMatched(publicKey []byte, did string) bool {

	if didTemp, err := getDIDAddress(publicKey); err != nil {
		return false
	} else {
		if didTemp != did {
			return false
		}
		return true
	}
}

//DIDDoc *id.DIDDoc
func (v *validator) getPublicKeyByVerificationMethod(VerificationMethod, ID string,
	PublicKey []id.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) (string, error) {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == ID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if compactSymbol == getUriSegment(keyString) {
					return keyString, nil
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return "", err
				}
				didPublicKeyInfo := new(id.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return "", err
				}
				if compactSymbol == getUriSegment(didPublicKeyInfo.ID) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			default:
				return "", errors.New(" invalid  auth.(type)")
			}
		}
	} else {
		//2, check is proofUriSegment public key come from controller
		if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
			//2.1 is controller exist
			for _, controller := range controllerArray {
				if controller == prefixDid {
					//get controllerDID last store data
					TranasactionData, err := v.GetLastDIDTxData(prefixDid)
					if err != nil {
						return "", err
					}
					if TranasactionData == nil {
						return "", errors.New("prefixDid DID not exist in level db")
					}
					doc := TranasactionData.Operation.DIDDoc
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, doc.Authentication, doc.PublicKey)
					if pubKeyBase58Str == "" {
						return "", errors.New("multi controller NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := id.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
					if IsMatched(PublicKey, did) {
						return pubKeyBase58Str, nil
					}
				}
			}
		} else if controller, bController := Controller.(string); bController == true {
			if controller == prefixDid {
				//get controllerDID last store data
				TranasactionData, err := v.GetLastDIDTxData(prefixDid)
				if err != nil {
					return "", err
				}
				if TranasactionData == nil {
					return "", errors.New("prefixDid DID not exist in level db")
				}
				payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return "", errors.New("single controller NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := id.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
				if IsMatched(PublicKey, did) {
					return pubKeyBase58Str, nil
				}
			}
		}
	}
	return "", errors.New(" wrong public key by VerificationMethod ")
}

func Unmarshal(src, target interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func (v *validator) checkCustomizedDIDTicketProof(verifyDoc *id.DIDDoc, Proof interface{}) ([]*id.TicketProof,
	error) {
	DIDProofArray := make([]*id.TicketProof, 0)
	CustomizedDIDProof := &id.TicketProof{}
	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("checkCustomizedDIDAllVerificationMethod Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

func (v *validator) checkCustomizedDIDAllVerificationMethod(verifyDoc *id.DIDDoc, Proof interface{}) ([]*id.DocProof,
	error) {
	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//var DIDProofArray []*id.DocProof
	DIDProofArray := make([]*id.DocProof, 0)

	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &id.DocProof{}
	//var bExist bool

	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.Creator, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.Creator, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("checkCustomizedDIDAllVerificationMethod Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

func (v *validator) checkCustomizedDIDInnerAllVerificationMethod(verifyDoc *id.DIDDoc, Proof interface{}) ([]*id.DocProof,
	error) {
	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	var DIDProofArray []*id.DocProof
	var CustomizedDIDProof *id.DocProof
	var bExist bool
	bDIDProofArray := false
	if DIDProofArray, bDIDProofArray = Proof.([]*id.DocProof); bDIDProofArray == true {
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.Type, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if CustomizedDIDProof, bExist = Proof.(*id.DocProof); bExist == true {
		if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.Type, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("checkCustomizedDIDInnerAllVerificationMethod Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

//Proof VerificationMethod must be in DIDDoc Authentication or
//is  controller primary key
//txPrefixDID is customized ID
func (v *validator) checkCustomizedDIDVerificationMethod(VerificationMethod, txPrefixDID string,
	publicKey []id.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) error {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == txPrefixDID {
		var pubkeyCount int
		for i := 0; i < len(publicKey); i++ {
			if compactSymbol == getUriSegment(publicKey[i].ID) {
				pubKeyByte := base58.Decode(publicKey[i].PublicKeyBase58)
				//get did address
				didAddress, err := getDIDAddress(pubKeyByte)
				if err != nil {
					return err
				}
				//didAddress must equal address in DID
				if didAddress != v.Store.GetDIDFromUri(txPrefixDID) {
					return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
				}
				pubkeyCount++
				break
			}
		}
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if compactSymbol == getUriSegment(keyString) {
					pubkeyCount++
					//publicKey is primary and is reference in authentication
					if pubkeyCount == 2 {
						pubkeyCount--
					}
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return err
				}
				didPublicKeyInfo := new(id.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return err
				}
				if compactSymbol == getUriSegment(didPublicKeyInfo.ID) {
					pubkeyCount++
				}
			default:
				return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] invalid  auth.(type)")
			}
		}
		if pubkeyCount == 1 {
			return nil
		}
	} else {
		//2, check is proofUriSegment public key come from controller
		if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
			//2.1 is controller exist
			for _, controller := range controllerArray {
				if controller == prefixDid {
					//get controllerDID last store data
					TranasactionData, err := v.GetLastDIDTxData(prefixDid)
					if err != nil {
						return err
					}
					if TranasactionData == nil {
						return errors.New("prefixDid GetLastDIDTxData not exist in level db")
					}
					payload := TranasactionData.Operation.DIDDoc
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := id.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
					if IsMatched(PublicKey, did) {
						return nil
					}
				}
			}
		} else if controller, bController := Controller.(string); bController == true {
			if controller == prefixDid {
				//get controllerDID last store data
				TranasactionData, err := v.GetLastDIDTxData(prefixDid)
				if err != nil {
					return err
				}
				if TranasactionData == nil {
					return errors.New("prefixDid LastDIDTxData not exist in level db")
				}
				payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := id.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
				if IsMatched(PublicKey, did) {
					return nil
				}
			}
		}
	}
	return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] wrong public key by VerificationMethod ")
}

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func (v *validator) checkVerificationMethodV1(VerificationMethod string,
	DIDDoc *id.DIDDoc) error {
	proofUriSegment := getUriSegment(VerificationMethod)

	masterPubKeyVerifyOk := false
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress != v.Store.GetDIDFromUri(DIDDoc.ID) {
				return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
			}
			masterPubKeyVerifyOk = true
			break
		}
	}

	for _, auth := range DIDDoc.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				return nil
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(id.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return nil
			}
		default:
			return errors.New("[ID checkVerificationMethodV1] invalid  auth.(type)")
		}
	}
	if masterPubKeyVerifyOk {
		return nil
	}
	return errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func (v *validator) checkCustomIDVerificationMethod(VerificationMethod string,
	DIDDoc *id.DIDDoc) error {
	proofUriSegment := getUriSegment(VerificationMethod)

	var pubkeyCount int
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress != v.Store.GetDIDFromUri(DIDDoc.ID) {
				return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
			}
			pubkeyCount++
			break
		}
	}

	for _, auth := range DIDDoc.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				pubkeyCount++
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(id.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				pubkeyCount++
			}
		default:
			return errors.New("[ID checkVerificationMethodV1] invalid  auth.(type)")
		}
	}
	if pubkeyCount == 1 {
		return nil
	}
	return errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

func (v *validator) GetLastCustomizedDIDTxData(customizedDID string) (*id.DIDTransactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	return v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
}

func (v *validator) GetLastDIDTxData(issuerDID string) (*id.DIDTransactionData, error) {
	did := v.Store.GetDIDFromUri(issuerDID)
	if did == "" {
		return nil, errors.New("WRONG DID FORMAT")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(did)
	lastTXData, err := v.Store.GetLastDIDTxData(buf.Bytes())

	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return lastTXData, nil
}

// issuerDID can be did or customizeDID
func (v *validator) getIssuerPublicKey(issuerDID, idURI string) ([]byte, error) {
	var publicKey []byte
	if txData, err := v.GetLastDIDTxData(issuerDID); err != nil {
		return nil, err
	} else {
		if txData == nil {
			issuerTxData, err := v.GetLastCustomizedDIDTxData(issuerDID)
			if err != nil {
				return []byte{}, err
			}
			if issuerTxData == nil {
				return []byte{}, errors.New("LEVELDB NOT FIND issuerDID TX DATA")
			}
			DIDDoc := issuerTxData.Operation.GetDIDDoc()
			pubKeyStr := getPublicKey(idURI, DIDDoc.Authentication, DIDDoc.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)

		} else {
			DIDDoc := txData.Operation.DIDDoc
			pubKeyStr := getPublicKey(idURI, DIDDoc.Authentication, DIDDoc.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)
		}

	}
	return publicKey, nil
}

func (v *validator) getCredentialIssuer(DID string, cridential *id.VerifiableCredentialDoc) string {
	realIssuer := cridential.Issuer
	if cridential.Issuer == "" {
		creSub := cridential.CredentialSubject.(map[string]interface{})
		for k, v := range creSub {
			if k == id.ID_STRING {
				realIssuer = v.(string)
				break
			}
		}
		if realIssuer == "" {
			realIssuer = DID
		}
	}
	return realIssuer
}

/*
	Brief introduction:
		1, get public from Issuer2, verify credential sign
	Details:
		1，Traverse each credential, if Issuer is an empty string, use the ID in CredentialSubject,
			if it is still an empty string, use the outermost DID, indicating that it is a self-declared Credential
		2, if Issuer is not empty string, get Issuer public key from db，
	       if Issuer is not exist  check if realIssuer is ID,
           if so get public key from Authentication or PublicKey
        3, verify credential sign. if ID is compact format must Completion ID
*/
func (v *validator) checkVerifiableCredentials(DID string, VerifiableCredential []id.VerifiableCredential,
	Authentication []interface{}, PublicKey []id.DIDPublicKeyInfo, controller interface{}) error {
	var issuerPublicKey, issuerCode, signature []byte
	var err error
	isDID := v.isResiteredDID(DID)
	//1，Traverse each credential, if Issuer is an empty string, use the DID in CredentialSubject,
	//if it is still an empty string, use the outermost DID, indicating that it is a self-declared Credential
	for _, cridential := range VerifiableCredential {
		realIssuer := cridential.Issuer
		proof := cridential.GetDIDProofInfo()
		if cridential.Issuer == "" {
			creSub := cridential.CredentialSubject.(map[string]interface{})
			for k, v := range creSub {
				if k == id.ID_STRING {
					realIssuer = v.(string)
					break
				}
			}
			if realIssuer == "" {
				realIssuer = DID
			}
			pubKeyStr := getPublicKey(proof.VerificationMethod, Authentication, PublicKey)
			if pubKeyStr == "" {
				return errors.New("checkVerifiableCredentials NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		} else {
			//2,if Issuer is not empty string, get Issuer public key from db，
			//if Issuer is not exist  check if realIssuer is DID,
			//if so get public key from Authentication or PublicKey
			if issuerPublicKey, err = v.getIssuerPublicKey(realIssuer, proof.VerificationMethod); err != nil {
				if realIssuer == DID {
					if isDID {
						pubKeyStr := getPublicKey(proof.VerificationMethod, Authentication, PublicKey)
						if pubKeyStr == "" {
							return errors.New("DID NOT FIND PUBLIC KEY OF VerificationMethod")
						}
						issuerPublicKey = base58.Decode(pubKeyStr)
					} else {

						pubKeyStr, _ := v.getPublicKeyByVerificationMethod(proof.VerificationMethod, realIssuer, PublicKey,
							Authentication, controller)
						if pubKeyStr == "" {
							return errors.New("realIssuer NOT FIND PUBLIC KEY OF VerificationMethod")
						}
						issuerPublicKey = base58.Decode(pubKeyStr)
					}

				} else {
					return err
				}
			}
		}
		if issuerCode, err = getCodeByPubKey(issuerPublicKey); err != nil {
			return err
		}
		//get signature
		if signature, err = base64url.DecodeString(proof.Signature); err != nil {
			return err
		}
		//if DID is compact format must Completion DID
		cridential.CompleteCompact(DID)
		// verify proof
		var success bool

		success, err = v.VerifyByVM(cridential.VerifiableCredentialData, issuerCode, signature)
		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		return nil
	}
	return nil
}

func getDIDByPublicKey(publicKey []byte) (*common.Uint168, error) {
	pk, _ := crypto.DecodePoint(publicKey)
	redeemScript, err := contract.CreateStandardRedeemScript(pk)
	if err != nil {
		return nil, err
	}
	return getDIDHashByCode(redeemScript)
}

func getDIDHashByCode(code []byte) (*common.Uint168, error) {
	ct1, error := CreateCRDIDContractByCode(code)
	if error != nil {
		return nil, error
	}
	return ct1.ToProgramHash(), error
}

func CreateCRIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

func getDIDAddress(publicKey []byte) (string, error) {
	code, err := getCodeByPubKey(publicKey)
	if err != nil {
		return "", err
	}
	newCode := make([]byte, len(code))
	copy(newCode, code)
	didCode := append(newCode[:len(newCode)-1], 0xAD)
	ct1, err2 := CreateCRIDContractByCode(didCode)
	if err2 != nil {
		return "", err
	}
	return ct1.ToProgramHash().ToAddress()
}

func getCIDAdress(publicKey []byte) (string, error) {
	hash, err := getDIDByPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return hash.ToAddress()
}

func getAuthorizatedPublicKey(proof *id.Proof, DIDDoc *id.DIDDoc) string {
	proofUriSegment := getUriSegment(proof.VerificationMethod)

	for _, pkInfo := range DIDDoc.PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range DIDDoc.Authorization {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				for i := 0; i < len(DIDDoc.PublicKey); i++ {
					if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
						return DIDDoc.PublicKey[i].PublicKeyBase58
					}
				}
				return ""
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return ""
			}
			didPublicKeyInfo := new(id.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return ""
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58
			}
		default:
			return ""
		}
	}

	return ""
}

//todo use VerificationMethod correspond public key
func getPublicKey(VerificationMethod string, Authentication []interface{}, PublicKey []id.DIDPublicKeyInfo) string {
	proofUriSegment := getUriSegment(VerificationMethod)

	for _, pkInfo := range PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range Authentication {
		switch auth.(type) {
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return ""
			}
			didPublicKeyInfo := new(id.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return ""
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58
			}
		default:
			return ""
		}
	}
	return ""
}

func getParameterBySignature(signature []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)
	return buf.Bytes()
}

func getCodeByPubKey(publicKey []byte) ([]byte, error) {
	pk, err := crypto.DecodePoint(publicKey)
	if err != nil {
		return nil, err
	}
	code, err2 := contract.CreateStandardRedeemScript(pk)
	if err2 != nil {
		return nil, err2
	}
	return code, nil
}

func (v *validator) VerifyByVM(iDateContainer interfaces.IDataContainer,
	code []byte,
	signature []byte) (bool, error) {
	se := vm.NewExecutionEngine(iDateContainer,
		new(vm.CryptoECDsa), vm.MAXSTEPS, nil, nil)

	se.LoadScript(code, false)
	se.LoadScript(getParameterBySignature(signature), true)
	//execute program on VM
	se.Execute()

	if se.GetState() != vm.HALT {
		return false, errors.New("[VM] Finish State not equal to HALT")
	}

	if se.GetEvaluationStack().Count() != 1 {
		return false, errors.New("[VM] Execute Engine Stack Count Error")
	}

	success := se.GetExecuteResult()
	if !success {
		return false, errors.New("[VM] Check Sig FALSE")
	}
	return true, nil
}

//check operateion create---->db must not have
//                 update----->db must have
func (v *validator) checkDIDOperation(header *id.Header,
	idUri string) error {
	did := v.Store.GetDIDFromUri(idUri)
	if did == "" {
		return errors.New("WRONG DID FORMAT")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(did)

	if v.Store.IsDIDDeactivated(did) {
		return errors.New("DID is deactivated")
	}

	lastTXData, err := v.Store.GetLastDIDTxData(buf.Bytes())

	dbExist := true
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == id.Create_DID_Operation {
			return errors.New("DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == id.Update_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := service.ToReversedString(*hash)

			if lastTXData.TXID != preTXID {
				return errors.New("PreviousTxid IS NOT CORRECT")
			}
		}
	} else {
		if header.Operation == id.Update_DID_Operation {
			return errors.New("DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//1, if one credential is declear can not be declear again
//if one credential is revoke  can not be decalre or revoke again
func (v *validator) checkDeclareVerifiableCredentialOperation(header *id.Header,
	CredentialID string) error {
	if header.Operation != id.Declare_Verifiable_Credential_Operation {
		return errors.New("checkDeclareVerifiableCredentialOperation WRONG OPERATION")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(CredentialID)
	_, err := v.Store.GetLastVerifiableCredentialTxData(buf.Bytes())
	dbExist := true
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		return errors.New("VerifiableCredential WRONG OPERATION ALREADY Declare")
	}

	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func (v *validator) checkCustomizedDIDOperation(header *id.Header,
	customizedDID string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	lastTXData, err := v.Store.GetLastCustomizedDIDTxData(buf.Bytes())

	dbExist := true
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == id.Create_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == id.Update_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := service.ToReversedString(*hash)

			if lastTXData.TXID != preTXID {
				return errors.New("Customized DID PreviousTxid IS NOT CORRECT")
			}
		}
	} else {
		if header.Operation == id.Update_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

func GetMultisignMN(mulstiSign string) (int, int, error) {
	index := strings.LastIndex(mulstiSign, ":")
	if index == -1 {
		return 0, 0, errors.New("mulstiSign did not have :")
	}
	M, err := strconv.Atoi(mulstiSign[0:index])
	if err != nil {
		return 0, 0, err
	}
	N, err := strconv.Atoi(mulstiSign[index+1:])
	if err != nil {
		return 0, 0, err
	}
	return M, N, nil
}

func GetVerifiableCredentialID(cridential *id.VerifiableCredentialDoc) string {
	creSub := cridential.CredentialSubject.(map[string]interface{})
	ID := ""
	for k, v := range creSub {
		if k == id.ID_STRING {
			ID = v.(string)
			break
		}
	}
	return ID
}

func (v *validator) isDID(didDoc *id.DIDDoc) bool {

	if !strings.HasPrefix(didDoc.ID, id.DID_ELASTOS_PREFIX) {
		return false
	}
	idString := id.GetDIDFromUri(didDoc.ID)

	for _, pkInfo := range didDoc.PublicKey {
		publicKey := base58.Decode(pkInfo.PublicKeyBase58)
		if IsMatched(publicKey, idString) {
			return true
		}
	}
	return false
}

func (v *validator) isResiteredDID(ID string) bool {
	TranasactionData, err := v.GetLastDIDTxData(ID)
	// err  not registerd
	if err != nil {
		return false
	}
	//not find 	  not registerd
	if TranasactionData == nil {
		return false
	}
	// registered
	return true
}

func helper(VerificationMethod string, Controller interface{}) bool {
	prefixDid, _ := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == prefixDid {
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == prefixDid {
			return true
		}
	}
	return false
}

func (v *validator) isIDVerifMethodMatch(verificationMethod, ID string) bool {
	return isDIDVerifMethodMatch(verificationMethod, ID) || v.isCustomizedVerifMethodMatch(verificationMethod, ID)
}

func isDIDVerifMethodMatch(verificationMethod, ID string) bool {
	return strings.Contains(verificationMethod, ID)
}

//here issuer must be customizdDID
func (v *validator) isCustomizedVerifMethodMatch(verificationMethod, issuer string) bool {

	prefixDid, _ := GetDIDAndCompactSymbolFromUri(verificationMethod)

	issuerTxData, err := v.GetLastCustomizedDIDTxData(issuer)
	if err != nil {
		return false
	}
	if issuerTxData == nil {
		return false
	}
	Controller := issuerTxData.Operation.DIDDoc.Controller
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == prefixDid {
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == prefixDid {
			return true
		}
	}
	return false
}

// Is VerificationMethod of proof array and ID  matched
func (v *validator) isIDsVerifMethodMatch(Proof interface{}, ID string) bool {
	//var DIDProofArray []*id.Proof
	if DIDProofArray, bDIDProofArray := Proof.([]*id.Proof); bDIDProofArray == true {
		for _, proof := range DIDProofArray {
			if !v.isIDVerifMethodMatch(proof.VerificationMethod, ID) {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func (v *validator) checkDIDAllMethod(receiver, issuer string, credPayload *id.DIDPayload) (*id.Proof, error) {
	//var DIDProofArray []*id.Proof
	proof := credPayload.Proof
	if credPayload.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
		//如果Proof是数组，在revoke的情况下Proof的签名可以是receiver或者issuer的
		//receiver或者issuer都即可能是did也可能是短名字
		//则VerificationMethod指定的应该是issuer的key
		//receiver或者issuer都即可能是did也可能是短名字
		verifMethod := proof.VerificationMethod
		if v.isIDVerifMethodMatch(verifMethod, issuer) || v.isIDVerifMethodMatch(verifMethod, receiver) {
			return &proof, nil
		}
		return nil, errors.New("revoke  Proof and id is not matched")
	} else if credPayload.Header.Operation == id.Declare_Verifiable_Credential_Operation {
		if !v.isIDVerifMethodMatch(proof.VerificationMethod, receiver) {
			return nil, errors.New("proof  receiver not match")
		}
		return &proof, nil
	} else {
		return nil, errors.New("invalid Operation")
	}
}

//receiveDID is did
//issuer can be did or customizeddid(one/more controller)
//if it is revoke  issuer can deactive
//VerificationMethod should be did
func (v *validator) checkDIDVerifiableCredential(receiveDID, issuerID string,
	credPayload *id.DIDPayload) error {
	receiverDIDTx, err := v.GetLastDIDTxData(receiveDID)
	if err != nil {
		return err
	}
	if receiverDIDTx == nil {
		return errors.New("isRegiseredDID DID not exist in level db")
	}
	//issuerID is did or not
	//issuerIsDID := v.isResiteredDID(issuerID)
	verifyDIDDoc := receiverDIDTx.Operation.DIDDoc
	var proof *id.Proof
	if proof, err = v.checkDIDAllMethod(receiveDID, issuerID, credPayload); err != nil {
		return err
	}

	//get  public key
	publicKeyBase58 := getPublicKey(proof.VerificationMethod,
		verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("checkDIDVerifiableCredential Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(proof.Signature)

	var success bool
	success, err = v.VerifyByVM(credPayload, code, signature)

	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}

	if err = v.checkVerifiableCredentials(receiveDID, []id.VerifiableCredential{*credPayload.CredentialDoc.VerifiableCredential},
		verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey, nil); err != nil {
		return err
	}
	return nil
}

func (v *validator) checkCustomizedDIDVerifiableCredential(customizedDID string, payload *id.DIDPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	verifyDoc, err := v.getVerifyDocMultisign(customizedDID)
	if err != nil {
		return err
	}

	//M,
	//var N int
	N := 0
	if verifyDoc.MultiSig != "" {
		_, N, err = GetMultisignMN(verifyDoc.MultiSig)
		if err != nil {
			return err
		}
	}
	//doc := customizedDIDPayload.DIDDoc

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller

	DIDProofArray, err := v.checkCustomizedDIDAllVerificationMethod(verifyDoc, payload.Proof)
	if err != nil {
		return err
	}

	//3, proof multisign verify
	err = v.checkCustomIDInnerProof(DIDProofArray, payload, N, verifyDoc)
	if err != nil {
		//return err
	}
	//4, Verifiable credential
	if err = v.checkVerifiableCredentials(verifyDoc.ID, payload.DIDDoc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller); err != nil {
		return err
	}
	return nil
}

func (v *validator) checkVerifiableCredential(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	payload, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid DIDPayload")
	}

	_, err := time.Parse(time.RFC3339, payload.CredentialDoc.ExpirationDate)
	if err != nil {
		return errors.New("invalid ExpirationDate")
	}

	switch payload.Header.Operation {
	case id.Declare_Verifiable_Credential_Operation:
		return v.checkDeclareVerifiableCredential(payload)
	case id.Revoke_Verifiable_Credential_Operation:
		return v.checkRevokeVerifiableCredential(payload)
	}

	return errors.New("invalid operation")
}

func (v *validator) checkDeclareVerifiableCredential(payload *id.DIDPayload) error {
	//1, if one credential is declear can not be declear again
	//if one credential is revoke  can not be decalre or revoke again
	// this is the receiver id  todo
	receiverID := GetVerifiableCredentialID(payload.CredentialDoc)
	credentialID := payload.CredentialDoc.ID
	issuer := v.getCredentialIssuer(receiverID, payload.CredentialDoc)
	if err := v.checkDeclareVerifiableCredentialOperation(&payload.Header, credentialID); err != nil {
		return err
	}

	////todo This customized did and register did are mutually exclusive
	////todo check expires

	// if it is "create" use now m/n and public key otherwise use last time m/n and public key
	// get credential target ID , Authentication , PublicKey, m,n of multisign   (isDID/customized did)
	//
	isDID := v.isResiteredDID(receiverID)
	if isDID {
		////issuer can revoke credential
		//if payload.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
		//	if CustomizedDIDProof, bExist := payload.Proof.(*id.Proof); bExist == true {
		//		if strings.Contains(CustomizedDIDProof.VerificationMethod, issuer) {
		//			return v.checkDIDVerifiableCredential(receiverID, issuer, payload)
		//		}
		//	}
		//}
		//receiverID is did, but issuer may have one or more controllers  todo more controllers
		return v.checkDIDVerifiableCredential(receiverID, issuer, payload)
	} else {
		return v.checkCustomizedDIDVerifiableCredential(receiverID, payload)
	}
}

func (v *validator) checkRevokeVerifiableCredential(payload *id.DIDPayload) error {
	credentialID := payload.Payload

	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)
	lastTXData, err := v.Store.GetLastVerifiableCredentialTxData(buf.Bytes())

	dbExist := true
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if lastTXData == nil {
			return errors.New("checkRevokeVerifiableCredential invalid last transaction")
		}
		if lastTXData.Operation.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
			return errors.New("VerifiableCredential revoked again")
		}

		// check if owner or issuer send this transaction
		owner := GetVerifiableCredentialID(lastTXData.Operation.CredentialDoc)
		issuer := v.getCredentialIssuer(owner, lastTXData.Operation.CredentialDoc)

		return v.checkDIDVerifiableCredential(owner, issuer, payload)
	}

	return nil
}

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func (v *validator) getVerifyDocMultisign(customizedID string) (*id.DIDDoc, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedID)
	transactionData, err := v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return transactionData.Operation.DIDDoc, nil
}

func (v *validator) checkCustomIDTicketProof(ticketProofArray []*id.TicketProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *id.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, ticketProof := range ticketProofArray {
		//get  public key
		publicKeyBase58, _ := v.getPublicKeyByVerificationMethod(ticketProof.VerificationMethod, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDTicketProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := getCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(ticketProof.Signature)

		var success bool
		success, err = v.VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < N {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < N")
	}
	return nil
}

//3, proof multisign verify
func (v *validator) checkCustomIDInnerProof(DIDProofArray []*id.DocProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *id.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := v.getPublicKeyByVerificationMethod(CustomizedDIDProof.Creator, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := getCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool
		fmt.Println("publicKeyBase58 ", publicKeyBase58)
		fmt.Println("signature ", CustomizedDIDProof.SignatureValue)

		success, err = v.VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < N {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < N")
	}
	return nil
}

func (v *validator) checkCustomizedDIDAvailable(cPayload *id.DIDPayload) error {
	reservedCustomIDs, err := v.spvService.GetReservedCustomIDs()
	if err != nil {
		return err
	}
	receivedCustomIDs, err := v.spvService.GetReceivedCustomIDs()
	if err != nil {
		return err
	}

	if _, ok := reservedCustomIDs[cPayload.DIDDoc.ID]; ok {
		if customDID, ok := receivedCustomIDs[cPayload.DIDDoc.ID]; ok {
			rcDID, err := customDID.ToAddress()
			if err != nil {
				return errors.New("invalid customDID in db")
			}
			if did, ok := cPayload.DIDDoc.Controller.(string); ok {
				if !strings.Contains(did, rcDID) {
					return errors.New("invalid controller did")
				}
			} else {
				// customID need be one of the controller.
				var controllerCount int
				if dids, ok := cPayload.DIDDoc.Controller.([]string); ok {
					for _, did := range dids {
						if strings.Contains(did, rcDID) {
							controllerCount++
						}
					}
				} else {
					return errors.New("invalid controller")
				}
				if controllerCount != 1 {
					return errors.New("not in controller")
				}
				// customID need be one oof the signature
				if proofs, ok := cPayload.DIDDoc.Proof.([]*id.DocProof); ok {
					var invalidProofCount int
					for _, proof := range proofs {
						if strings.Contains(proof.Creator, rcDID) {
							invalidProofCount++
						}
					}
					if invalidProofCount == 0 {
						return errors.New("there is no signature of custom ID")
					} else if invalidProofCount > 1 {
						return errors.New("there is duplicated signature of custom ID")
					}
				} else if proof, ok := cPayload.DIDDoc.Proof.(*id.DocProof); ok {
					if !strings.Contains(proof.Creator, rcDID) {
						return errors.New("there is no signature of custom ID")
					}
				} else {
					//error
					return errors.New("invalid Proof type")
				}
			}
		}
	}

	return nil
}

func (v *validator) checkTicketAvailable(cPayload *id.DIDPayload,
	customID string, lastTxHash common.Uint256, N int, verifyDoc *id.DIDDoc) error {
	// check customID
	if cPayload.Ticket.CustomID != customID {
		return errors.New("invalid ID in ticket")
	}

	// 'to' need exist in controller
	to := cPayload.Ticket.To
	var existInController bool
	if controllerArray, ok := cPayload.DIDDoc.Controller.([]interface{}); ok {
		for _, controller := range controllerArray {
			if controller == to {
				existInController = true
			}
		}
	} else if controller, ok := cPayload.DIDDoc.Controller.(string); ok {
		if controller == to {
			existInController = true
		}
	}
	if !existInController {
		return errors.New("'to' is not in controller")
	}

	// 'to' need exist in proof
	dIDProofArray := make([]*id.DocProof, 0)
	customizedDIDProof := &id.DocProof{}
	existInProof := false
	if err := Unmarshal(cPayload.DIDDoc.Proof, &dIDProofArray); err == nil {
		for _, proof := range dIDProofArray {
			if proof.Creator == to {
				existInProof = true
			}
		}

	} else if err := Unmarshal(cPayload.DIDDoc.Proof, customizedDIDProof); err == nil {
		if customizedDIDProof.Creator == to {
			existInProof = true
		}
	}
	if !existInProof {
		return errors.New("'to' is not in proof")
	}

	// check transactionID
	if cPayload.Ticket.TransactionID != lastTxHash.String() {
		return errors.New("invalid TransactionID of ticket")
	}

	// check proof
	if err := v.checkTicketProof(cPayload.Ticket, N, verifyDoc, cPayload.Ticket.Proof); err != nil {
		return errors.New("invalid proof of ticket")
	}

	return nil
}

func (v *validator) checkTicketProof(ticket *id.CustomIDTicket, N int,
	verifyDoc *id.DIDDoc, Proof interface{}) error {
	ticketProofArray, err := v.checkCustomizedDIDTicketProof(verifyDoc, Proof)
	if err != nil {
		return err
	}

	err = v.checkCustomIDTicketProof(ticketProofArray, ticket, N, verifyDoc)
	if err != nil {
		return err
	}

	return nil
}

func (v *validator) checkRegisterDIDTxFee(txn *types.Transaction) error {
	operation, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid Operation")
	}
	feeHelper := v.GetFeeHelper()
	if feeHelper == nil {
		return errors.New("feeHelper == nil")
	}

	txFee, err := feeHelper.GetTxFee(txn, v.GetParams().ElaAssetId)
	if err != nil {
		return err
	}
	//2. calculate the  fee that one cutomized did tx should paid
	payload := operation.DIDDoc
	buf := new(bytes.Buffer)
	operation.Serialize(buf, id.DIDVersion)
	needFee := v.getIDTxFee(payload.ID, payload.Expires, operation.Header.Operation, nil, buf.Len())
	if txFee < needFee {
		return errors.New("invalid txFee")
	}

	//check fee and should paid fee
	return nil
}

func (v *validator) checkCustomizedDIDTxFee(txn *types.Transaction) error {
	payload, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid DIDPayload")
	}
	feeHelper := v.GetFeeHelper()
	if feeHelper == nil {
		return errors.New("feeHelper == nil")
	}

	txFee, err := feeHelper.GetTxFee(txn, v.GetParams().ElaAssetId)
	if err != nil {
		return err
	}
	//2. calculate the  fee that one cutomized did tx should paid
	doc := payload.DIDDoc
	buf := new(bytes.Buffer)
	payload.Serialize(buf, id.DIDVersion)
	needFee := v.getIDTxFee(doc.ID, doc.Expires, payload.Header.Operation, doc.Controller, buf.Len())
	if txFee < needFee {
		return errors.New("invalid txFee")
	}

	//check fee and should paid fee
	return nil
}

func getCustomizedDIDLenFactor(ID string) float64 {
	len := len(ID)
	if len == 0 {
		return 0.3
	} else if len == 1 {
		return 6400
	} else if len == 2 {
		return 3200
	} else if len == 3 {
		return 1200
	} else if len <= 32 {
		//100 - [(n-1) / 8 ]
		return 100 - ((float64(len) - 1) / 8)
	} else if len <= 64 {
		//93 + [(n-1) / 8 ]
		return 93 + ((float64(len) - 1) / 8)
	} else {
		//100 * (n-59) / 3
		return 100 * ((float64(len) - 59) / 2)
	}
}

func (v *validator) getValidPeriodFactor(Expires string) float64 {

	expiresTime, _ := time.Parse(time.RFC3339, Expires)
	days := expiresTime.Day() - v.Chain.MedianTimePast.Day()
	if days < 180 {
		expiresTime.Add(180 * 24 * time.Hour)
	}

	years := float64(expiresTime.Year() - v.Chain.MedianTimePast.Year())

	if years <= 0 {
		return 1
	}
	lifeRate := float64(0)
	if years < 1 {
		lifeRate = float64(years * ((100 - 3*math.Log2(1)) / 100))
	} else {
		lifeRate = float64(years * ((100 - 3*math.Log2(years)) / 100))
	}
	return lifeRate

}

func getOperationFactor(operation string) float64 {
	factor := float64(0)
	switch operation {
	case "CREATE":
		factor = 1
	case "UPDATE":
		factor = 0.8
	case "TRANSFER":
		factor = 1.2
	case "DEACTIVATE":
		factor = 0.3
	case "DECLARE":
		factor = 1
	case "REVOKE":
		factor = 0.3
	default:
		factor = 1
	}
	return factor
}

func getSizeFactor(payLoadSize int) float64 {
	factor := float64(0)
	if payLoadSize <= 1024 {
		factor = 1
	} else if payLoadSize <= 32*1024 {
		factor = math.Log10(float64(payLoadSize/1024))/2 + 1
	} else {
		factor = float64(payLoadSize/1024)*0.9*math.Log10(float64(payLoadSize/1024)) - 33.4
	}
	return factor
}

func getControllerFactor(controller interface{}) float64 {
	if controller == nil {
		return 0
	}
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		controllerLen := len(controllerArray)
		if controllerLen <= 1 {
			return float64(controllerLen)
		}
		//M=2**(m+3)
		return 2 * (float64(controllerLen) + 3)
	}
	return 1

}

func getControllerLength(controller interface{}) int {
	if controllerArray, ok := controller.([]interface{}); ok == true {
		return len(controllerArray)
	}
	return 1
}

//Payload
//ID  Expires Controller Operation Payload interface
func (v *validator) getIDTxFee(customID, expires, operation string, controller interface{}, payloadLen int) common.Fixed64 {
	//A id lenght
	A := getCustomizedDIDLenFactor(customID)
	//B Valid period
	B := v.getValidPeriodFactor(expires)
	//C operation create or update
	C := getOperationFactor(operation)
	//M controller sign number
	M := getControllerFactor(controller)
	//E doc size
	E := getSizeFactor(payloadLen)
	//F factor got from cr proposal
	F := v.didParam.CustomIDFeeRate
	feeRate, _ := v.spvService.GetRateOfCustomIDFee()
	if feeRate != 0 {
		F = feeRate
	}

	fee := (A*B*C*M + E) * float64(F)
	return common.Fixed64(fee)
}

func (v *validator) checkCustomizedDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {

	customizedDIDPayload, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid DIDPayload")
	}

	// check Custom ID available?
	if err := v.checkCustomizedDIDAvailable(customizedDIDPayload); err != nil {
		return err
	}

	//check txn fee
	if err := v.checkCustomizedDIDTxFee(txn); err != nil {
		return err
	}

	//check Expires must be  format RFC3339
	_, err := time.Parse(time.RFC3339, customizedDIDPayload.DIDDoc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}
	//if this customized did is already exist operation should not be create
	//if this customized did is not exist operation should not be update
	if err := v.checkCustomizedDIDOperation(&customizedDIDPayload.Header,
		customizedDIDPayload.DIDDoc.ID); err != nil {
		return err
	}

	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	var verifyDoc *id.DIDDoc
	if customizedDIDPayload.Header.Operation == id.Create_DID_Operation ||
		customizedDIDPayload.Header.Operation == id.Transfer_DID_Operation {
		verifyDoc = customizedDIDPayload.DIDDoc
	} else {
		verifyDoc, err = v.getVerifyDocMultisign(customizedDIDPayload.DIDDoc.ID)
		if err != nil {
			return err
		}
	}

	// check payload.proof
	if err := v.checkCustomizedDIDVerificationMethod(
		customizedDIDPayload.Proof.VerificationMethod, verifyDoc.ID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
		return err
	}

	if err := v.checkCustomIDOuterProof(customizedDIDPayload, verifyDoc); err != nil {
		return err
	}

	//todo This custoized did and register did are mutually exclusive
	//todo check expires

	N := 0
	multisignStr := verifyDoc.MultiSig
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}

	// check ticket when operation is 'Transfer'
	if customizedDIDPayload.Header.Operation == id.Transfer_DID_Operation {
		buf := new(bytes.Buffer)
		buf.WriteString(verifyDoc.ID)
		lastTxHash, err := v.Store.GetLastCustomizedDIDTxHash(buf.Bytes())
		if err != nil {
			return err
		}
		if err := v.checkTicketAvailable(customizedDIDPayload,
			verifyDoc.ID, lastTxHash, N, verifyDoc); err != nil {
			return err
		}
	}

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller

	DIDProofArray, err := v.checkCustomizedDIDAllVerificationMethod(verifyDoc, customizedDIDPayload.DIDDoc.Proof)
	if err != nil {
		return err
	}

	//3, Verifiable credential
	if err = v.checkVerifiableCredentials(
		customizedDIDPayload.DIDDoc.ID, customizedDIDPayload.DIDDoc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller); err != nil {
		return err
	}
	//4, proof multisign verify
	err = v.checkCustomIDInnerProof(DIDProofArray, customizedDIDPayload.DIDDoc.DIDPayloadData, N, verifyDoc)
	if err != nil {
		return err
	}
	return nil

}

func (v *validator) checkCustomIDOuterProof(txPayload *id.DIDPayload, verifyDoc *id.DIDDoc) error {
	//get  public key
	publicKeyBase58, _ := v.getPublicKeyByVerificationMethod(txPayload.Proof.VerificationMethod, verifyDoc.ID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
	if publicKeyBase58 == "" {
		return errors.New("checkCustomIDOuterProof not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(txPayload.Proof.Signature)

	var success bool
	success, err = v.VerifyByVM(txPayload, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkCustomIDProof[VM] Check Sig FALSE")
	}
	return nil
}

func (v *validator) checkDIDTransaction(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	//payload type check
	if txn.TxType != id.DIDOperation {
		return nil
	}
	p, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid DID payload")
	}

	switch p.Header.Operation {
	case id.Create_DID_Operation, id.Update_DID_Operation:
		var isRegisterDID bool
		isRegisterDID = v.isDID(p.DIDDoc)
		if isRegisterDID {
			return v.checkRegisterDID(txn, height, mainChainHeight)
		} else {
			return v.checkCustomizedDID(txn, height, mainChainHeight)
		}

	case id.Transfer_DID_Operation:
		return v.checkCustomizedDID(txn, height, mainChainHeight)

	case id.Deactivate_DID_Operation:
		return v.checkDeactivateDID(txn, height, mainChainHeight)

	case id.Declare_Verifiable_Credential_Operation, id.Revoke_Verifiable_Credential_Operation:
		return v.checkVerifiableCredential(txn, height, mainChainHeight)
	}
	return errors.New("invalid Operation")
}

func (v *validator) checkRegisterDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	p, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid Operation")
	}
	_, err := time.Parse(time.RFC3339, p.DIDDoc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	//check txn fee
	if err := v.checkRegisterDIDTxFee(txn); err != nil {
		return err
	}

	if err := v.checkDIDOperation(&p.Header,
		p.DIDDoc.ID); err != nil {
		return err
	}
	if height < v.didParam.CheckRegisterDIDHeight {
		if err := v.checkVerificationMethodV0(&p.Proof,
			p.DIDDoc); err != nil {
			return err
		}
	} else {
		if err := v.checkVerificationMethodV1(p.Proof.VerificationMethod,
			p.DIDDoc); err != nil {
			return err
		}
	}
	// todo checkVerificationMethodV2 use pubkeyCount++

	//get  public key
	publicKeyBase58 := getPublicKey(p.Proof.VerificationMethod,
		p.DIDDoc.Authentication, p.DIDDoc.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(p.Proof.Signature)

	var success bool
	success, err = v.VerifyByVM(p, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkDIDTransaction [VM]  Check Sig FALSE")
	}
	if height >= v.didParam.VerifiableCredentialHeight {
		doc := p.DIDDoc
		if err = v.checkVerifiableCredentials(doc.ID, doc.VerifiableCredential,
			doc.Authentication, doc.PublicKey, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v *validator) checkDeactivateDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	deactivateDIDOpt, ok := txn.Payload.(*id.DIDPayload)
	if !ok {
		return errors.New("invalid DeactivateDIDOptPayload")
	}
	targetDIDUri := deactivateDIDOpt.Payload
	targetDID := v.Store.GetDIDFromUri(targetDIDUri)
	if targetDID == "" {
		return errors.New("WRONG DID FORMAT")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(targetDID)
	lastTXData, err := v.Store.GetLastDIDTxData(buf.Bytes())
	if err != nil {
		return err
	}

	//do not deactivage a did who was already deactivate
	if v.Store.IsDIDDeactivated(targetDID) {
		return errors.New("DID WAS AREADY DEACTIVE")
	}

	//get  public key
	publicKeyBase58 := getAuthorizatedPublicKey(&deactivateDIDOpt.Proof,
		lastTXData.Operation.DIDDoc)
	if publicKeyBase58 == "" {
		return errors.New("Not find the publickey verificationMethod   ")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(deactivateDIDOpt.Proof.Signature)

	var success bool
	success, err = v.VerifyByVM(deactivateDIDOpt, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}
	return nil
}
