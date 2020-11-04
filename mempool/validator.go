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
	CheckRegisterDIDFuncName   = "checkregisterdid"
	CheckUpdateDIDFuncName     = "checkupdatedid"
	CheckDeactivateDIDFuncName = "checkdeactivatedid"
	CheckCustomizedDIDFuncName = "checkcustomizeddid"
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
	return &val
}

func (v *validator) checkTransactionPayload(txn *types.Transaction) error {
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
	default:
		return errors.New("[ID CheckTransactionPayload] [txValidator],invalidate transaction payload type.")
	}
	return nil
}

func checkAmountPrecise(amount common.Fixed64, precision byte, assetPrecision byte) bool {
	return amount.IntValue()%int64(math.Pow10(int(assetPrecision-precision))) == 0
}

func (v *validator) checkTransactionOutput(txn *types.Transaction) error {
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

func (v *validator) checkTransactionSignature(txn *types.Transaction) error {
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
	return idURI[0:index], idURI[index:]
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

func (v *validator) getCustomizedDIDPublicKeyByVerificationMethod(proof *id.DIDProofInfo,
	payloadInfo *id.CustomizedDIDPayload) (string, error) {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(proof.VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == payloadInfo.ID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range payloadInfo.Authentication {
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
				return "", errors.New("[ID checkCustomizedDIDVerificationMethod] invalid  auth.(type)")
			}
		}
	} else {
		//2, check is proofUriSegment public key come from controller

		if controllerArray, bControllerArray := payloadInfo.Controller.([]interface{}); bControllerArray == true {
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
					pubKeyBase58Str := getPublicKey(proof.VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return "", errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
					if IsMatched(PublicKey, did) {
						return pubKeyBase58Str, nil
					}
				}
			}
		} else if controller, bController := payloadInfo.Controller.(string); bController == true {
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
				pubKeyBase58Str := getPublicKey(proof.VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return "", errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := id.GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
				if IsMatched(PublicKey, did) {
					return pubKeyBase58Str, nil
				}
			}
		}
	}
	return "", errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

//DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
//is come from controller
func (v *validator) checkCustomizedDIDVerificationMethod(proof *id.DIDProofInfo,
	payloadInfo *id.CustomizedDIDPayload) error {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(proof.VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == payloadInfo.ID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range payloadInfo.Authentication {
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
				return errors.New("[ID checkCustomizedDIDVerificationMethod] invalid  auth.(type)")
			}
		}
	} else {
		//2, check is proofUriSegment public key come from controller

		if controllerArray, bControllerArray := payloadInfo.Controller.([]interface{}); bControllerArray == true {
			//2.1 is controller exist
			for _, controller := range controllerArray {
				if controller == prefixDid {
					//get controllerDID last store data
					TranasactionData, err := v.GetLastDIDTxData(prefixDid)
					if err != nil {
						return err
					}
					if TranasactionData == nil {
						return errors.New("prefixDid DID not exist in level db")
					}
					payload := TranasactionData.Operation.PayloadInfo
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(proof.VerificationMethod, payload.Authentication, payload.PublicKey)
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
		} else if controller, bController := payloadInfo.Controller.(string); bController == true {
			if controller == prefixDid {
				//get controllerDID last store data
				TranasactionData, err := v.GetLastDIDTxData(prefixDid)
				if err != nil {
					return err
				}
				if TranasactionData == nil {
					return errors.New("prefixDid DID not exist in level db")
				}
				payload := TranasactionData.Operation.PayloadInfo
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(proof.VerificationMethod, payload.Authentication, payload.PublicKey)
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
	return errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

//DIDProofInfo VerificationMethod must be in DIDPayloadInfo Authentication or
//is did publickKey
func (v *validator) checkVerificationMethodV1(proof *id.DIDProofInfo,
	payloadInfo *id.DIDPayloadInfo) error {
	proofUriSegment := getUriSegment(proof.VerificationMethod)

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

func (v *validator) checkVeriﬁableCredential(ID string, VerifiableCredential []id.VerifiableCredential,
	Authentication []interface{}, PublicKey []id.DIDPublicKeyInfo) error {
	var issuerPublicKey, issuerCode, signature []byte
	var err error

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
				realIssuer = ID
			}
			if issuerPublicKey, err = v.getIssuerPublicKey(realIssuer, proof.VerificationMethod); err != nil {
				return err
			}

		} else {
			//get issuer public key
			if issuerPublicKey, err = v.getIssuerPublicKey(realIssuer, proof.VerificationMethod); err != nil {
				if realIssuer == ID {
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
		//payloadInfo.ID
		cridential.VerifiableCredentialData.CompleteCompact(ID)
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

//check operateion create---->db must not have
//                 update----->db must have
func (v *validator) checkCustomizedDIDOperation(header *id.CustomizedDIDHeaderInfo,
	idUri string) error {
	//did := v.Store.GetDIDFromUri(idUri)
	//if did == "" {
	//	return errors.New("WRONG DID FORMAT")
	//}

	buf := new(bytes.Buffer)
	buf.WriteString(idUri)
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

func (v *validator) checkCustomizedDID(txn *types.Transaction) error {
	//payload type check
	if txn.TxType != id.CustomizedDID {
		return nil
	}
	payloadDidInfo, ok := txn.Payload.(*id.CustomizedDIDOperation)
	if !ok {
		return errors.New("invalid CustomizedDIDOperation")
	}

	_, err := time.Parse(time.RFC3339, payloadDidInfo.PayloadInfo.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	if err := v.checkCustomizedDIDOperation(&payloadDidInfo.Header,
		payloadDidInfo.GetPayloadInfo().ID); err != nil {
		return err
	}

	//todo 这个custoized did 在registerdid中不能存在， 在registerdid 跟customized did互斥
	//检查expires todo

	//todo 如果是create则以这次的m/n和公钥验证，否则以上一次的数据记录m/n
	var verifyPayloadinfo *id.CustomizedDIDPayload
	curPayloadInfo := payloadDidInfo.GetPayloadInfo()
	//M,
	var N, verifyOkCount int
	if payloadDidInfo.Header.Operation == id.Create_Customized_DID_Operation {
		verifyPayloadinfo = curPayloadInfo
		if payloadDidInfo.Header.Multisign != "" {
			_, N, err = GetMultisignMN(payloadDidInfo.Header.Multisign)
			if err != nil {
				return err
			}
		}
	} else {
		did := v.Store.GetDIDFromUri(payloadDidInfo.GetPayloadInfo().ID)
		if did == "" {
			return errors.New("WRONG DID FORMAT")
		}

		buf := new(bytes.Buffer)
		buf.WriteString(did)
		transactionData, err := v.Store.GetLastCustomizedDIDTxData(buf.Bytes())
		if err != nil {
			return err
		}
		verifyPayloadinfo = transactionData.Operation.GetPayloadInfo()
		_, N, err = GetMultisignMN(transactionData.Operation.Header.Multisign)
		if err != nil {
			return err
		}
	}

	//localCurrentHeight := v.Store.GetHeight()
	//
	var DIDProofArray []*id.DIDProofInfo
	var CustomizedDIDProof *id.DIDProofInfo
	var bExist bool

	bDIDProofArray := false
	if DIDProofArray, bDIDProofArray = payloadDidInfo.Proof.([]*id.DIDProofInfo); bDIDProofArray == true {
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof,
				payloadDidInfo.GetPayloadInfo()); err != nil {
				return err
			}
		}
	} else if CustomizedDIDProof, bExist = payloadDidInfo.Proof.(*id.DIDProofInfo); bExist == true {
		if err := v.checkCustomizedDIDVerificationMethod(CustomizedDIDProof,
			payloadDidInfo.GetPayloadInfo()); err != nil {
			return err
		}
	} else {
		//error
		return errors.New("Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}

	//遍历每一个proof 根据m/n进行验签的
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		//todo
		publicKeyBase58, _ := v.getCustomizedDIDPublicKeyByVerificationMethod(CustomizedDIDProof, verifyPayloadinfo)
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
		success, err = v.VerifyByVM(payloadDidInfo, code, signature)

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

	//todo 是否需要考虑用前一个交易的公钥啥的？
	if err = v.checkVeriﬁableCredential(curPayloadInfo.ID, curPayloadInfo.VerifiableCredential,
		curPayloadInfo.Authentication, curPayloadInfo.PublicKey); err != nil {
		return err
	}
	return nil

}

func (v *validator) checkRegisterDID(txn *types.Transaction) error {
	//payload type check
	if txn.TxType != id.RegisterDID {
		return nil
	}
	payloadDidInfo, ok := txn.Payload.(*id.Operation)
	if !ok {
		return errors.New("invalid Operation")
	}

	_, err := time.Parse(time.RFC3339, payloadDidInfo.PayloadInfo.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	if err := v.checkDIDOperation(&payloadDidInfo.Header,
		payloadDidInfo.PayloadInfo.ID); err != nil {
		return err
	}
	localCurrentHeight := v.Store.GetHeight()
	if localCurrentHeight < v.didParam.CheckRegisterDIDHeight {
		if err := v.checkVerificationMethodV0(&payloadDidInfo.Proof,
			payloadDidInfo.PayloadInfo); err != nil {
			return err
		}
	} else {
		if err := v.checkVerificationMethodV1(&payloadDidInfo.Proof,
			payloadDidInfo.PayloadInfo); err != nil {
			return err
		}
	}

	//get  public key
	publicKeyBase58 := getPublicKey(payloadDidInfo.Proof.VerificationMethod,
		payloadDidInfo.PayloadInfo.Authentication, payloadDidInfo.PayloadInfo.PublicKey)
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
	signature, _ := base64url.DecodeString(payloadDidInfo.Proof.Signature)

	var success bool
	success, err = v.VerifyByVM(payloadDidInfo, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkRegisterDID [VM]  Check Sig FALSE")
	}
	if localCurrentHeight >= v.didParam.VeriﬁableCredentialHeight {
		payloadInfo := payloadDidInfo.PayloadInfo
		if err = v.checkVeriﬁableCredential(payloadInfo.ID, payloadInfo.VerifiableCredential,
			payloadInfo.Authentication, payloadInfo.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

func (v *validator) checkDeactivateDID(txn *types.Transaction) error {
	//payload type check
	if txn.TxType != id.DeactivateDID {
		return nil
	}
	deactivateDIDOpt, ok := txn.Payload.(*id.DeactivateDIDOptPayload)
	if !ok {
		return errors.New("invalid Operation")
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
