package mempool

import (
	"bytes"
	"encoding/json"
	"errors"
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
	CheckRegisterDIDFuncName             = "checkregisterdid"
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
	val.RegisterContextFunc(CheckRegisterDIDFuncName, val.checkRegisterDID)
	val.RegisterContextFunc(CheckDeactivateDIDFuncName, val.checkDeactivateDID)
	val.RegisterContextFunc(CheckCustomizedDIDFuncName, val.checkCustomizedDID)
	val.RegisterContextFunc(CheckVerifiableCredentialFuncName, val.checkVerifiableCredential)
	val.RegisterContextFunc(CheckDeactivateCustomizedDIDFuncName, val.checkCustomizedDIDDeactivateTX)

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
	case *id.Operation:
	case *id.DeactivateDIDOptPayload:
	case *id.CustomizedDIDOperation:
	case *id.VerifiableCredentialPayload:
	case *id.DeactivateCustomizedDIDPayload:
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

//DIDProofInfo VerificationMethod must be in DIDPayloadInfo Authentication or
//is did publickKey
func (v *validator) checkVerificationMethodV0(proof *id.DIDProofInfo,
	payloadInfo *id.DIDPayloadInfo) error {
	proofUriSegment := getUriSegment(proof.VerificationMethod)
	for _, auth := range payloadInfo.Authentication {
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
	for i := 0; i < len(payloadInfo.PublicKey); i++ {
		//get PublicKeyBase58 accord to VerificationMethod
		if proofUriSegment == getUriSegment(payloadInfo.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(payloadInfo.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getCIDAdress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress == v.Store.GetDIDFromUri(payloadInfo.ID) {
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

//payloadInfo *id.CustomizedDIDPayload
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
					payload := TranasactionData.Operation.PayloadInfo
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return "", errors.New(" NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
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
				payload := TranasactionData.Operation.PayloadInfo
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return "", errors.New(" NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
				if IsMatched(PublicKey, did) {
					return pubKeyBase58Str, nil
				}
			}
		}
	}
	return "", errors.New(" wrong public key by VerificationMethod ")
}

func (v *validator) checkCustomizedDIDAllVerificationMethod(doc *id.CustomizedDIDPayload, Proof interface{}) ([]*id.DIDProofInfo,
	error) {
	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller
	//doc := payload.Doc
	var DIDProofArray []*id.DIDProofInfo
	var CustomizedDIDProof *id.DIDProofInfo
	var bExist bool
	bDIDProofArray := false
	if DIDProofArray, bDIDProofArray = Proof.([]*id.DIDProofInfo); bDIDProofArray == true {
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.VerificationMethod, doc.CustomID,
				doc.PublicKey, doc.Authentication, doc.Controller); err != nil {
				return nil, err
			}
		}
	} else if CustomizedDIDProof, bExist = Proof.(*id.DIDProofInfo); bExist == true {
		if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof.VerificationMethod, doc.CustomID,
			doc.PublicKey, doc.Authentication, doc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

//DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
//is  controller primary key
//txPrefixDID is customized ID
func (v *validator) checkCustomizedDIDVerificationMethod(VerificationMethod, txPrefixDID string,
	PublicKey []id.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) error {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == txPrefixDID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if compactSymbol == getUriSegment(keyString) {
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
				if compactSymbol == getUriSegment(didPublicKeyInfo.ID) {
					return nil
				}
			default:
				return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] invalid  auth.(type)")
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
						return err
					}
					if TranasactionData == nil {
						return errors.New("prefixDid GetLastDIDTxData not exist in level db")
					}
					payload := TranasactionData.Operation.PayloadInfo
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
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
				payload := TranasactionData.Operation.PayloadInfo
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
				if IsMatched(PublicKey, did) {
					return nil
				}
			}
		}
	}
	return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] wrong public key by VerificationMethod ")
}

//DIDProofInfo VerificationMethod must be in DIDPayloadInfo Authentication or
//is did publickKey
func (v *validator) checkVerificationMethodV1(VerificationMethod string,
	payloadInfo *id.DIDPayloadInfo) error {
	proofUriSegment := getUriSegment(VerificationMethod)

	masterPubKeyVerifyOk := false
	for i := 0; i < len(payloadInfo.PublicKey); i++ {
		if proofUriSegment == getUriSegment(payloadInfo.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(payloadInfo.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress != v.Store.GetDIDFromUri(payloadInfo.ID) {
				return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
			}
			masterPubKeyVerifyOk = true
			break
		}
	}

	for _, auth := range payloadInfo.Authentication {
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

func (v *validator) GetLastCustomizedDIDTxData(customizedDID string) (*id.CustomizedDIDTranasactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	return v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
}

func (v *validator) GetLastDIDTxData(issuerDID string) (*id.TranasactionData, error) {
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

func (v *validator) getIssuerPublicKey(issuerDID, idURI string) ([]byte, error) {
	var publicKey []byte
	if txData, err := v.GetLastDIDTxData(issuerDID); err != nil {
		return nil, err
	} else {
		if txData == nil {
			return nil, errors.New("LEVELDB NOT FIND issuerDID TX DATA")
		}
		payloadInfo := txData.Operation.PayloadInfo
		pubKeyStr := getPublicKey(idURI, payloadInfo.Authentication, payloadInfo.PublicKey)
		if pubKeyStr == "" {
			return []byte{}, errors.New("NOT FIND PUBLIC KEY OF VerificationMethod")
		}
		publicKey = base58.Decode(pubKeyStr)
	}
	return publicKey, nil
}

func (v *validator) getCredentialIssuer(DID string, cridential *id.VerifiableCredential) string {
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
func (v *validator) checkVeriﬁableCredential(DID string, VerifiableCredential []id.VerifiableCredential,
	Authentication []interface{}, PublicKey []id.DIDPublicKeyInfo) error {
	var issuerPublicKey, issuerCode, signature []byte
	var err error

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
				return errors.New("NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		} else {
			//2,if Issuer is not empty string, get Issuer public key from db，
			//if Issuer is not exist  check if realIssuer is DID,
			//if so get public key from Authentication or PublicKey
			if issuerPublicKey, err = v.getIssuerPublicKey(realIssuer, proof.VerificationMethod); err != nil {
				if realIssuer == DID {
					pubKeyStr := getPublicKey(proof.VerificationMethod, Authentication, PublicKey)
					if pubKeyStr == "" {
						return errors.New("NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					issuerPublicKey = base58.Decode(pubKeyStr)
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
		cridential.VerifiableCredentialData.CompleteCompact(DID)
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

func getAuthorizatedPublicKey(proof *id.DIDProofInfo, payloadInfo *id.DIDPayloadInfo) string {
	proofUriSegment := getUriSegment(proof.VerificationMethod)

	for _, pkInfo := range payloadInfo.PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range payloadInfo.Authorization {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				for i := 0; i < len(payloadInfo.PublicKey); i++ {
					if proofUriSegment == getUriSegment(payloadInfo.PublicKey[i].ID) {
						return payloadInfo.PublicKey[i].PublicKeyBase58
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
func (v *validator) checkDIDOperation(header *id.DIDHeaderInfo,
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
func (v *validator) checkVerifiableCredentialOperation(header *id.CustomizedDIDHeaderInfo,
	CredentialID string) error {
	if header.Operation != id.Declare_Verifiable_Credential_Operation &&
		header.Operation != id.Revoke_Verifiable_Credential_Operation {
		return errors.New("checkVerifiableCredentialOperation WRONG OPERATION")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(CredentialID)
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
		if header.Operation == id.Declare_Verifiable_Credential_Operation {
			return errors.New("VerifiableCredential WRONG OPERATION ALREADY Declare")
		} else if lastTXData.Operation.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
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
		if header.Operation == id.Revoke_Verifiable_Credential_Operation {
			return errors.New(" Revoke WRONG Verifiable_Credential NOT EXIST")
		}
	}
	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func (v *validator) checkCustomizedDIDOperation(header *id.CustomizedDIDHeaderInfo,
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
		if header.Operation == id.Create_Customized_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == id.Update_Customized_DID_Operation {
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
		if header.Operation == id.Update_Customized_DID_Operation {
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
	M, err := strconv.Atoi(mulstiSign[0 : index+1])
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
	Controller := issuerTxData.Operation.Doc.Controller
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
	//var DIDProofArray []*id.DIDProofInfo
	if DIDProofArray, bDIDProofArray := Proof.([]*id.DIDProofInfo); bDIDProofArray == true {
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

func (v *validator) checkDIDAllMethod(receiver, issuer string, credPayload *id.VerifiableCredentialPayload) (
	[]*id.DIDProofInfo, error) {
	//var DIDProofArray []*id.DIDProofInfo
	Proof := credPayload.Proof
	if credPayload.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
		//如果Proof是数组，在revoke的情况下Proof的签名可以是receiver或者issuer的
		//receiver或者issuer都即可能是did也可能是短名字
		if DIDProofArray, bDIDProofArray := Proof.([]*id.DIDProofInfo); bDIDProofArray == true {
			if v.isIDsVerifMethodMatch(Proof, issuer) || v.isIDsVerifMethodMatch(Proof, receiver) {
				return DIDProofArray, nil
			}
			return nil, errors.New("revoke bDIDProofArray Proof and id is not matched")
		} else if proof, bExist := Proof.(*id.DIDProofInfo); bExist == true {
			//则VerificationMethod指定的应该是issuer的key
			//receiver或者issuer都即可能是did也可能是短名字
			verifMethod := proof.VerificationMethod
			if v.isIDVerifMethodMatch(verifMethod, issuer) || v.isIDVerifMethodMatch(verifMethod, receiver) {
				DIDProofArray = append(DIDProofArray, proof)
				return DIDProofArray, nil
			}
			return nil, errors.New("revoke  Proof and id is not matched")

		} else {
			return nil, errors.New("revoke invalid proof")
		}
	} else if credPayload.Header.Operation == id.Declare_Verifiable_Credential_Operation {
		if DIDProofArray, bDIDProofArray := Proof.([]*id.DIDProofInfo); bDIDProofArray == true {
			for _, proof := range DIDProofArray {
				if !v.isIDVerifMethodMatch(proof.VerificationMethod, receiver) {
					return nil, errors.New("DIDProofArray receiver VerificationMethod not match")
				}
			}
			return DIDProofArray, nil
		} else if proof, bExist := Proof.(*id.DIDProofInfo); bExist == true {
			if !v.isIDVerifMethodMatch(proof.VerificationMethod, receiver) {
				return nil, errors.New("proof  receiver not match")
			}
			DIDProofArray = append(DIDProofArray, proof)

			return DIDProofArray, nil
		} else {
			return nil, errors.New("invalid proof")
		}
	} else {
		return nil, errors.New("invalid Operation")
	}
	//return nil
}

//receiveDID is did
//issuer can be did or customizeddid(one/more controller)
//if it is revoke  issuer can deactive
//VerificationMethod should be did
func (v *validator) checkDIDVerifiableCredential(receiveDID, issuerID string,
	credPayload *id.VerifiableCredentialPayload) error {
	receiverDIDTx, err := v.GetLastDIDTxData(receiveDID)
	if err != nil {
		return err
	}
	if receiverDIDTx == nil {
		return errors.New("isRegiseredDID DID not exist in level db")
	}
	//issuerID is did or not
	//issuerIsDID := v.isResiteredDID(issuerID)
	verifyPayloadinfo := receiverDIDTx.Operation.PayloadInfo
	var DIDProofArray []*id.DIDProofInfo

	if DIDProofArray, err = v.checkDIDAllMethod(receiveDID, issuerID, credPayload); err != nil {
		return err
	}

	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58 := getPublicKey(CustomizedDIDProof.VerificationMethod,
			verifyPayloadinfo.Authentication, verifyPayloadinfo.PublicKey)
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
		signature, _ := base64url.DecodeString(CustomizedDIDProof.Signature)

		var success bool
		success, err = v.VerifyByVM(credPayload, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
	}
	if err = v.checkVeriﬁableCredential(receiveDID, []id.VerifiableCredential{*credPayload.Doc.VerifiableCredential},
		verifyPayloadinfo.Authentication, verifyPayloadinfo.PublicKey); err != nil {
		return err
	}
	return nil
}

func (v *validator) checkCustomizedDIDVerifiableCredential(customizedDID string, payload *id.VerifiableCredentialPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.CustomizedDIDPayload
	verifyDoc, multisignStr, err := v.getVerifyDocMultisign(customizedDID)
	if err != nil {
		return err
	}

	//M,
	//var N int
	N := 0
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}
	//doc := customizedDIDPayload.Doc

	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller

	DIDProofArray, err := v.checkCustomizedDIDAllVerificationMethod(verifyDoc, payload.Proof)
	if err != nil {
		return err
	}

	//3, proof multisign verify
	err = v.checkCustomizedDIDProof(DIDProofArray, payload, N, verifyDoc)
	if err != nil {
		return err
	}
	//4, Verifiable credential
	if err = v.checkVeriﬁableCredential(verifyDoc.CustomID, []id.VerifiableCredential{*payload.Doc.VerifiableCredential},
		verifyDoc.Authentication, verifyDoc.PublicKey); err != nil {
		return err
	}
	return nil
}

func (v *validator) checkVerifiableCredential(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	//payload type check
	if txn.TxType != id.VerifiableCredentialTxType {
		return nil
	}
	payload, ok := txn.Payload.(*id.VerifiableCredentialPayload)
	if !ok {
		return errors.New("invalid CustomizedDIDOperation")
	}

	_, err := time.Parse(time.RFC3339, payload.Doc.ExpirationDate)
	if err != nil {
		return errors.New("invalid ExpirationDate")
	}
	//1, if one credential is declear can not be declear again
	//if one credential is revoke  can not be decalre or revoke again
	// this is the receiver id  todo
	receiverID := GetVerifiableCredentialID(payload.Doc)
	credentialID := payload.Doc.ID
	issuer := v.getCredentialIssuer(receiverID, payload.Doc.VerifiableCredential)
	//todo here should be credentialID
	if err := v.checkVerifiableCredentialOperation(&payload.Header, credentialID); err != nil {
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
		//	if CustomizedDIDProof, bExist := payload.Proof.(*id.DIDProofInfo); bExist == true {
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

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func (v *validator) getVerifyDocMultisign(customizedID string) (*id.CustomizedDIDPayload,
	string, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedID)
	transactionData, err := v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
	if err != nil {
		return nil, "", err
	}
	return transactionData.Operation.Doc, transactionData.Operation.Header.Multisign, nil
}

//3, proof multisign verify
func (v *validator) checkCustomizedDIDProof(DIDProofArray []*id.DIDProofInfo, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *id.CustomizedDIDPayload) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := v.getPublicKeyByVerificationMethod(CustomizedDIDProof.VerificationMethod, verifyDoc.CustomID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
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
		signature, _ := base64url.DecodeString(CustomizedDIDProof.Signature)

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

func (v *validator) checkCustomizedDIDAvailable(cPayload *id.CustomizedDIDOperation) error {
	reservedCustomIDs, _ := v.spvService.GetReservedCustomIDs()
	receivedCustomIDs, _ := v.spvService.GetReceivedCustomIDs()

	for rsCustomID, _ := range reservedCustomIDs {
		if rsCustomID == cPayload.Doc.CustomID {
			// id count of controller need to be one
			if getControllerLength(cPayload.Doc.Controller) != 1 {
				return errors.New("invalid id count in controller")
			}
			//
			for rcCustomID, customDID := range receivedCustomIDs {
				if rcCustomID == cPayload.Doc.CustomID {
					did, ok := cPayload.Doc.Controller.(string)
					if !ok {
						return errors.New("invalid controller")
					}
					rcDID, err := customDID.ToAddress()
					if err != nil {
						return errors.New("invalid customDID in db")
					}
					if !strings.Contains(did, rcDID) {
						return errors.New("invalid controller did")
					}
				}
			}
		}
	}

	return nil
}

func (v *validator) checkCustomizedDIDTxFee(txn *types.Transaction) error {
	customizedDIDPayload, ok := txn.Payload.(*id.CustomizedDIDOperation)
	if !ok {
		return errors.New("invalid CustomizedDIDOperation")
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
	needFee := v.getCustomizedDIDTxFee(customizedDIDPayload)
	if txFee <= needFee {
		return errors.New("invalid txFee")
	}

	//check fee and should paid fee
	return nil
}

func getCustomizedDIDLenFactor(customizeDID string) common.Fixed64 {
	len := len(customizeDID)

	if len == 1 {
		return 6400
	} else if len == 2 {
		return 3200
	} else if len >= 3 && len <= 32 {
		//100 - [(n-1) / 8 ]
		return 100 - ((common.Fixed64(len) - 1) / 8)
	} else if len >= 33 && len <= 64 {
		//93 + [(n-1) / 8 ]
		return 93 + ((common.Fixed64(len) - 1) / 8)
	} else {
		//100 * (n-59) / 3
		return 100 + ((common.Fixed64(len) - 59) / 3)
	}
}

func (v *validator) getValidPeriodFactor(Expires string) common.Fixed64 {

	expiresTime, _ := time.Parse(time.RFC3339, Expires)

	n := common.Fixed64(expiresTime.Year() - v.Chain.MedianTimePast.Year())
	//todo calculate vailid year, get median time
	//curMediantime := v.Chain.MedianTimePast
	//n := curMediantime - Expires
	//n := common.Fixed64(0)
	if n <= 0 {
		return 1
	}
	return n * (101 - n) / 100
}

func getOperationFactor(operation string) common.Fixed64 {
	if operation == id.Update_Customized_DID_Operation {
		return 12
	}
	return 10
}

func getControllerFactor(controller interface{}) common.Fixed64 {
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		controllerLen := len(controllerArray)
		if controllerLen <= 3 {
			return 1
		}
		//M=2**(m-3)
		return 2 * (common.Fixed64(controllerLen) - 3)
	}
	return 1

}

func getControllerLength(controller interface{}) int {
	if controllerArray, ok := controller.([]interface{}); ok == true {
		return len(controllerArray)
	}
	return 1
}

func (v *validator) getCustomizedDIDTxFee(customizedDIDPayload *id.CustomizedDIDOperation) common.Fixed64 {
	//A id lenght
	A := getCustomizedDIDLenFactor(customizedDIDPayload.Doc.CustomID)
	//B Valid period
	B := v.getValidPeriodFactor(customizedDIDPayload.Doc.Expires)
	//C operation create or update
	C := getOperationFactor(customizedDIDPayload.Header.Operation)
	//M controller sign number
	M := getControllerFactor(customizedDIDPayload.Doc.Controller)
	//E doc size
	buf := new(bytes.Buffer)
	customizedDIDPayload.Serialize(buf, id.CustomizedDIDVersion)
	E := common.Fixed64(buf.Len())
	//F factor got from cr proposal
	F := common.Fixed64(1)
	feeRate, err := v.spvService.GetRateOfCustomIDFee()
	if err == nil {
		F = feeRate
	}

	fee := (A*B*C*M + E) * F
	return fee
}

func (v *validator) checkCustomizedDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {

	//payload type check
	if txn.TxType != id.CustomizedDID {
		return nil
	}
	customizedDIDPayload, ok := txn.Payload.(*id.CustomizedDIDOperation)
	if !ok {
		return errors.New("invalid CustomizedDIDOperation")
	}

	// check Custom ID available?
	if err := v.checkCustomizedDIDAvailable(customizedDIDPayload); err != nil {
		return err
	}

	////check txn fee
	if err := v.checkCustomizedDIDTxFee(txn); err != nil {
		return err
	}

	//check Expires must be  format RFC3339
	_, err := time.Parse(time.RFC3339, customizedDIDPayload.Doc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}
	//if this customized did is already exist operation should not be create
	//if this customized did is not exist operation should not be update
	if err := v.checkCustomizedDIDOperation(&customizedDIDPayload.Header,
		customizedDIDPayload.Doc.CustomID); err != nil {
		return err
	}

	//todo This custoized did and register did are mutually exclusive
	//todo check expires

	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.CustomizedDIDPayload
	var verifyDoc *id.CustomizedDIDPayload
	var multisignStr string
	if customizedDIDPayload.Header.Operation == id.Create_Customized_DID_Operation {
		verifyDoc = customizedDIDPayload.Doc
		multisignStr = customizedDIDPayload.Header.Multisign
	} else {
		verifyDoc, multisignStr, err = v.getVerifyDocMultisign(customizedDIDPayload.Doc.CustomID)
		if err != nil {
			return err
		}
	}

	N := 0
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}
	doc := customizedDIDPayload.Doc

	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller

	DIDProofArray, err := v.checkCustomizedDIDAllVerificationMethod(customizedDIDPayload.Doc, customizedDIDPayload.Proof)
	if err != nil {
		return err
	}

	//3, proof multisign verify
	err = v.checkCustomizedDIDProof(DIDProofArray, customizedDIDPayload, N, verifyDoc)
	if err != nil {
		return err
	}
	//4, Verifiable credential
	if err = v.checkVeriﬁableCredential(doc.CustomID, doc.VerifiableCredential,
		doc.Authentication, doc.PublicKey); err != nil {
		return err
	}
	return nil

}

func (v *validator) checkRegisterDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	//payload type check
	if txn.TxType != id.RegisterDID {
		return nil
	}
	doc, ok := txn.Payload.(*id.Operation)
	if !ok {
		return errors.New("invalid Operation")
	}

	_, err := time.Parse(time.RFC3339, doc.PayloadInfo.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	if err := v.checkDIDOperation(&doc.Header,
		doc.PayloadInfo.ID); err != nil {
		return err
	}
	localCurrentHeight := v.Store.GetHeight()
	if localCurrentHeight < v.didParam.CheckRegisterDIDHeight {
		if err := v.checkVerificationMethodV0(&doc.Proof,
			doc.PayloadInfo); err != nil {
			return err
		}
	} else {
		if err := v.checkVerificationMethodV1(doc.Proof.VerificationMethod,
			doc.PayloadInfo); err != nil {
			return err
		}
	}

	//get  public key
	publicKeyBase58 := getPublicKey(doc.Proof.VerificationMethod,
		doc.PayloadInfo.Authentication, doc.PayloadInfo.PublicKey)
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
	signature, _ := base64url.DecodeString(doc.Proof.Signature)

	var success bool
	success, err = v.VerifyByVM(doc, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkRegisterDID [VM]  Check Sig FALSE")
	}
	if localCurrentHeight >= v.didParam.VeriﬁableCredentialHeight {
		payloadInfo := doc.PayloadInfo
		if err = v.checkVeriﬁableCredential(payloadInfo.ID, payloadInfo.VerifiableCredential,
			payloadInfo.Authentication, payloadInfo.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

//DeactivateCustomizedDIDTxType
func (v *validator) checkCustomizedDIDDeactivateTX(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	//payload type check
	if txn.TxType != id.DeactivateCustomizedDIDTxType {
		return nil
	}
	payload, ok := txn.Payload.(*id.DeactivateCustomizedDIDPayload)
	if !ok {
		return errors.New("invalid DeactivateCustomizedDIDPayload")
	}
	//targetDIDUri := payload.payload
	targetDID := payload.Payload
	if targetDID == "" {
		return errors.New("WRONG customizedDID FORMAT")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(targetDID)
	lastTXData, err := v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
	if err != nil {
		return err
	}

	//do not deactivage a did who was already deactivate
	if v.Store.IsCustomizedDIDDeactivated(targetDID) {
		return errors.New("customizedDID WAS AREADY DEACTIVE")
	}

	N := 0
	multisignStr := payload.Header.Multisign
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}
	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller

	DIDProofArray, err := v.checkCustomizedDIDAllVerificationMethod(lastTXData.Operation.Doc, payload.Proof)
	if err != nil {
		return err
	}

	//3, proof multisign verify
	err = v.checkCustomizedDIDProof(DIDProofArray, payload, N, lastTXData.Operation.Doc)
	if err != nil {
		return err
	}

	return nil
}

func (v *validator) checkDeactivateDID(txn *types.Transaction, height uint32, mainChainHeight uint32) error {
	//payload type check
	if txn.TxType != id.DeactivateDID {
		return nil
	}
	deactivateDIDOpt, ok := txn.Payload.(*id.DeactivateDIDOptPayload)
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
		lastTXData.Operation.PayloadInfo)
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
