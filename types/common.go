package types

import (
	"bytes"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ID/types/base64url"

	"github.com/btcsuite/btcutil/base58"
	"github.com/elastos/Elastos.ELA.SideChain/vm"
	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/crypto"
)

func GetDIDFromUri(idURI string) string {
	index := strings.LastIndex(idURI, ":")
	if index == -1 {
		return ""
	}
	return idURI[index+1:]
}

func IsURIHasPrefix(did string) bool {
	return strings.HasPrefix(did, DID_ELASTOS_PREFIX)
}

func LoadJsonData(fileName string) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return []byte{}, err
	}
	return fileData, nil
}

func IsDID(ID string, publicKey []DIDPublicKeyInfo) bool {
	if !strings.HasPrefix(ID, DID_ELASTOS_PREFIX) {
		return false
	}
	idString := GetDIDFromUri(ID)

	for _, pkInfo := range publicKey {
		publicKey := base58.Decode(pkInfo.PublicKeyBase58)
		if IsMatched(publicKey, idString) {
			return true
		}
	}
	return false
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

func IsPublickDIDMatched(PublicKeyBase58 string, did string) bool {

	pubKeyByte := base58.Decode(PublicKeyBase58)
	//get did address
	didAddress, err := getDIDAddress(pubKeyByte)
	if err != nil {
		return false
	}
	//didAddress must equal address in DID
	if didAddress != did {
		return false
	}
	return true
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

const PrefixCRDID contract.PrefixType = 0x67

func CreateCRIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

func CreateCRDIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

//URI Public string like verification method and creator and so on
func GetController(uriPublic string) (string, string) {
	index := strings.LastIndex(uriPublic, "#")
	if index == -1 {
		return "", ""
	}
	return uriPublic[:index], uriPublic[index:]
}

//#primary key is Fregment
func GetUriFregment(uri string) string {
	index := strings.LastIndex(uri, "#")
	if index == -1 {
		return ""
	}
	return uri[index:]
}

func CheckSignature(iDateContainer interfaces.IDataContainer, publickBase58, signatureBase64 string) error {
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publickBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(signatureBase64)

	var success bool
	success, err = VerifyByVM(iDateContainer, code, signature)

	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}
	return nil
}

func VerifyByVM(iDateContainer interfaces.IDataContainer,
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

func getParameterBySignature(signature []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)
	return buf.Bytes()
}

func GetDIDByPublicKey(publicKey []byte) (*common.Uint168, error) {
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

func GetDIDAddress(publicKey []byte) (string, error) {
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

func GetCIDAdress(publicKey []byte) (string, error) {
	hash, err := GetDIDByPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return hash.ToAddress()
}

func GetCodeByPubKey(publicKey []byte) ([]byte, error) {
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
