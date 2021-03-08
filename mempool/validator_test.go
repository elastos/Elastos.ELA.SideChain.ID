package mempool

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/suite"

	bc "github.com/elastos/Elastos.ELA.SideChain.ID/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain.ID/didjson"
	"github.com/elastos/Elastos.ELA.SideChain.ID/params"
	"github.com/elastos/Elastos.ELA.SideChain.ID/types"
	"github.com/elastos/Elastos.ELA.SideChain.ID/types/base64url"

	"github.com/elastos/Elastos.ELA.SideChain/blockchain"
	"github.com/elastos/Elastos.ELA.SideChain/config"
	"github.com/elastos/Elastos.ELA.SideChain/mempool"
	"github.com/elastos/Elastos.ELA.SideChain/spv"
	types2 "github.com/elastos/Elastos.ELA.SideChain/types"
	"github.com/elastos/Elastos.ELA/common"
	elacfg "github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/crypto"
)

type txValidatorTestSuite struct {
	suite.Suite
	validator validator
	Chain     *blockchain.BlockChain
}

func (s *txValidatorTestSuite) SetupSuite() {
	fmt.Println(os.RemoveAll("Chain_UnitTest"))
	fmt.Println(os.RemoveAll("data_spv"))

	idChainStore, err := bc.NewChainStore(params.
		GenesisBlock,
		"Chain_UnitTest")
	if err != nil {
		fmt.Println("failed to new NewChainStore")
		return
	}
	cfg := &mempool.Config{
		ChainParams: &config.Params{},
	}
	didParams := params.DIDParams{
		CheckRegisterDIDHeight:     0,
		VerifiableCredentialHeight: 0,
		CustomIDFeeRate:            1,
	}
	chainCfg := blockchain.Config{
		ChainParams: &config.Params{
			TargetTimespan:     1,
			TargetTimePerBlock: 2000000000,
			AdjustmentFactor:   1,
		},
		ChainStore: idChainStore.ChainStore,
		//GetTxFee:       txFeeHelper.GetTxFee,
		//CheckTxSanity:  txValidator.CheckTransactionSanity,
		//CheckTxContext: txValidator.CheckTransactionContext,
	}
	chain, err := blockchain.New(&chainCfg)
	if err != nil {
		fmt.Println("failed to new block chain")
		return
	}
	foundation, _ := common.Uint168FromAddress("8VYXVxKKSAxkmRrfmGpQR2Kc66XhG6m3ta")
	spvCfg := spv.Config{
		ChainParams: &elacfg.Params{
			GenesisBlock: elacfg.GenesisBlock(foundation),
			Foundation:   *foundation,
		},
		GenesisAddress: "8VYXVxKKSAxkmRrfmGpQR2Kc66XhG6m3ta",
	}
	spvService, err := spv.NewService(&spvCfg)
	if err != nil {
		fmt.Println("failed to new spvService")
		return
	}
	cfg.ChainStore = idChainStore.ChainStore
	txFeeHelper := mempool.NewFeeHelper(cfg)
	cfg.FeeHelper = txFeeHelper
	cfg.Chain = chain
	cfg.SpvService = spvService

	s.validator = *NewValidator(cfg, idChainStore, &didParams)
}

func TestTxValidatorTest(t *testing.T) {
	suite.Run(t, new(txValidatorTestSuite))
}

func (s *txValidatorTestSuite) TestCheckDIDDIDPayload() {
	//no create ------>update
	payloadUpdateDIDInfo := getPayloadUpdateDID()
	err := s.validator.checkDIDOperation(&payloadUpdateDIDInfo.Header,
		payloadUpdateDIDInfo.DIDDoc.ID)
	s.Equal(err.Error(), "DID WRONG OPERATION NOT EXIST")

	//doubale create
	payloadCreate := getPayloadCreateDID()
	err = s.validator.checkDIDOperation(&payloadCreate.Header,
		payloadCreate.DIDDoc.ID)
	s.NoError(err)
}

const (
	PayloadPrivateKey = "a38aa1f5f693a13ef0cf2f1c1c0155cbcdd9386f37b0000739f8cb50af601b7b"
	TxPrivateKey      = "5fe87de21fa55d751583bd0d74532c3cc679caf67919261e0c9b2a56f547c38d"
	publicKeyStr1     = "035d3adebb69db5fbd8005c37d225cd2fd9ec50ec7fcb38ff7c4fcf9b90455cf5f"
	publicKeyStr2     = "03bfd8bd2b10e887ec785360f9b329c2ae567975c784daca2f223cb19840b51914"
	publicKeyStr3     = "035d3adebb69db5fbd8005c37d225cd2fd9ec50ec7fcb38ff7c4fcf9b90455cf5f"
	ID                = "icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
	operationCreate   = "create"
	operationUpdate   = "update"
)

var (
	id1DocByts     []byte
	id11DocByts    []byte
	idUser1DocByts []byte
	idUser2DocByts []byte

	id2DocByts                      []byte
	id3DocByts                      []byte
	customizedDIDDocBytes1          []byte
	customizedDIDDocSingleContrller []byte

	customizedDIDDocBytes2                     []byte
	customizedVerifableCredDocBytes            []byte
	customizedVerifableCredControllersDocBytes []byte

	DIDVerifableCredDocBytes []byte
	headerPayloadByts        []byte
)

func init() {
	id1DocByts, _ = types.LoadJsonData("./testdata/document.compact.json")
	id11DocByts, _ = types.LoadJsonData("./testdata/issuer.id.json")
	idUser1DocByts, _ = types.LoadJsonData("./testdata/user1.id.json")
	idUser2DocByts, _ = types.LoadJsonData("./testdata/user2.id.json")

	id2DocByts, _ = types.LoadJsonData("./testdata/issuer.compact.json")
	id3DocByts, _ = types.LoadJsonData("./testdata/issuer.json")
	customizedDIDDocBytes1, _ = types.LoadJsonData("./testdata/customized_did_single_sign.json")
	customizedDIDDocSingleContrller, _ = types.LoadJsonData("./testdata/examplecorp.id.json") //

	customizedDIDDocBytes2, _ = types.LoadJsonData("./testdata/foo.id.json")
	customizedVerifableCredDocBytes, _ = types.LoadJsonData("./testdata/customized_did_verifiable_credential.json")
	DIDVerifableCredDocBytes, _ = types.LoadJsonData("./testdata/did_verifiable_credential.json")
	customizedVerifableCredControllersDocBytes, _ = types.LoadJsonData("./testdata/customized_did_verifiable_credential_controllers.json")

	//fmt.Println("customizedVerifableCredControllersDocBytes", string(customizedVerifableCredControllersDocBytes))
	id3DocByts, _ = types.LoadJsonData("./testdata/issuer.json")
	id3DocByts, _ = types.LoadJsonData("./testdata/issuer.json")
	headerPayloadByts, _ = types.LoadJsonData("./testdata/customized_did_multi_controllers.json")

}

var didPayloadBytes = []byte(
	`{
        "id" : "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
        "publicKey":[{ "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                       "publicKeyBase58":"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC"
                      },
					{
					   "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master",
					   "type":"ECDSAsecp256r1",
					   "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   }
                    ],
        "authentication":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],
        "expires" : "2023-02-10T17:00:00Z"
	}`)

//right
var didDIDDocBytes = []byte(
	`{
		"header":{"operation":"create","specification":"elastos/did/1.0"},
		"payload":"eyJpZCI6ImRpZDplbGFzdG9zOmliRjdnTXo1c2FObzM5MlVkN3pTQVZSblFyc0E3cHgydEMiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiJyb1FHRWVNdU1LZjdFeUFWa3loZjdxSnN5cmtGVXBUZ296WEQ4VkpoS2hpQyJ9XSwiYXV0aGVudGljYXRpb24iOlsiI3ByaW1hcnkiXSwiZXhwaXJlcyI6IjIwMjQtMTEtMjVUMDI6MDA6MDBaIn0",
		"proof":{
			"signature":"nrbHEEysMLzBR1mMVRjan9yfQtNGmK6Rqy7v9rvUpsJNoIMsY5JtEUiJvW82jW4xNlvOOEDI-VpLK_GCgjoUdQ",
			"verificationMethod":"#primary"
			}
	 }
`)

var errDIDDocBytes = []byte(
	`{
		"header":{"operation":"create","specification":"elastos/did/1.0"},
		"payload":"eyJpZCI6ImRpZDplbGFzdG9zOmlZUTZ1alBjd21UWmZqMmtOZmZXNEJDeXRKenlqbUpkRGQiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiJ6S1JYMWtOWGVYeTVuS3NyVTVtdVR3Z2Y3ZlhRYnhXZzdpUUtCdnBlS0dCUCJ9XSwiYXV0aGVudGljYXRpb24iOlsiI3ByaW1hcnkiXX0",
		"proof":{
			"signature":"nrbHEEysMLzBR1mMVRjan9yfQtNGmK6Rqy7v9rvUpsJNoIMsY5JtEUiJvW82jW4xNlvOOEDI-VpLK_GCgjoUdQ",
			"verificationMethod":"#primary"
			}
	 }
`)

func (s *txValidatorTestSuite) TestIDChainStore_CreateDIDTx() {
	tx := &types2.Transaction{
		TxType:         0x0a,
		PayloadVersion: 0,
		Payload:        getPayloadCreateDID(),
		Inputs:         nil,
		Outputs:        nil,
		LockTime:       0,
		Programs:       nil,
		Fee:            0,
		FeePerKB:       0,
	}
	fmt.Println(tx)
	data, _ := hex.DecodeString(publicKeyStr1)
	fmt.Println(data)

	fmt.Println(len(data))
	i, _ := types.GetDIDByPublicKey(data)
	didAddress, _ := i.ToAddress()
	fmt.Println("didAddress", didAddress)
	s.validator.didParam.CustomIDFeeRate = 0
	err := s.validator.checkDIDTransaction(tx, 0, 0)
	s.NoError(err)

	info := new(types.DIDPayload)
	didjson.Unmarshal(didDIDDocBytes, info)

	payloadBase64, _ := base64url.DecodeString(info.Payload)
	DIDDoc := new(types.DIDDoc)
	didjson.Unmarshal(payloadBase64, DIDDoc)
	info.DIDDoc = DIDDoc

	tx.Payload = info
	err = s.validator.checkDIDTransaction(tx, 0, 0)
	s.NoError(err)

	info.DIDDoc.Expires = "Mon Jan _2 15:04:05 2006"
	err = s.validator.checkDIDTransaction(tx, 0, 0)
	s.Error(err, "invalid Expires")

	info.DIDDoc.Expires = "2006-01-02T15:04:05Z07:00"
	err = s.validator.checkDIDTransaction(tx, 0, 0)
	s.Error(err, "invalid Expires")

	info.DIDDoc.Expires = "2018-06-30T12:00:00Z"
	err = s.validator.checkDIDTransaction(tx, 0, 0)
	s.NoError(err)

	info = new(types.DIDPayload)
	didjson.Unmarshal(errDIDDocBytes, info)

	payloadBase64, _ = base64url.DecodeString(info.Payload)
	DIDDoc = new(types.DIDDoc)
	didjson.Unmarshal(payloadBase64, DIDDoc)
	info.DIDDoc = DIDDoc

	tx.Payload = info
	err = s.validator.checkDIDTransaction(tx, 0, 0)
	s.Error(err, "invalid Expires")
}

func (s *txValidatorTestSuite) TestIDChainStore_DeactivateDIDTx() {
	didWithPrefix := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"
	//did := "iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"
	//did := s.validator.Store.GetDIDFromUri(didWithPrefix)

	verifDid := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default"

	txCreateDID := &types2.Transaction{
		TxType:         types.DIDOperation,
		PayloadVersion: 0,
		Payload:        getPayloadCreateDID(),
		Inputs:         nil,
		Outputs:        nil,
		LockTime:       0,
		Programs:       nil,
		Fee:            0,
		FeePerKB:       0,
	}

	txDeactivate := &types2.Transaction{
		TxType:         types.DIDOperation,
		PayloadVersion: 0,
		Payload:        getPayloadDeactivateDID(didWithPrefix, verifDid),
		Inputs:         nil,
		Outputs:        nil,
		LockTime:       0,
		Programs:       nil,
		Fee:            0,
		FeePerKB:       0,
	}
	//Deactive did  have no
	err := s.validator.checkDeactivateDID(txDeactivate, 0, 0)
	s.Error(err, "leveldb: not found")

	batch := s.validator.Store.ChainStore.NewBatch()
	s.validator.Store.PersistRegisterDIDTx(batch, []byte(didWithPrefix), txCreateDID, 0, 0)
	batch.Commit()

	err = s.validator.checkDeactivateDID(txDeactivate, 0, 0)
	s.NoError(err)

	//wrong public key to verify sign
	verifDid = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master"
	txDeactivateWrong := &types2.Transaction{
		TxType:         types.DIDOperation,
		PayloadVersion: 0,
		Payload:        getPayloadDeactivateDID(didWithPrefix, verifDid),
		Inputs:         nil,
		Outputs:        nil,
		LockTime:       0,
		Programs:       nil,
		Fee:            0,
		FeePerKB:       0,
	}

	err = s.validator.checkDeactivateDID(txDeactivateWrong, 0, 0)
	s.Error(err, "[VM] Check Sig FALSE")

	//deactive one deactivated did
	batch = s.validator.Store.ChainStore.NewBatch()
	s.validator.Store.PersistDeactivateDIDTx(batch, []byte(didWithPrefix))
	batch.Commit()
	err = s.validator.checkDeactivateDID(txDeactivateWrong, 0, 0)
	s.Error(err, "DID WAS AREADY DEACTIVE")

}

func (s *txValidatorTestSuite) TestGetIDFromUri() {
	validUriFormat := "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
	id := types.GetDIDFromUri(validUriFormat)
	s.Equal(id, "icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN")

	InvalidUriFormat := "icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
	id = types.GetDIDFromUri(InvalidUriFormat)
	s.Equal(id, "")
}

func getPayloadCreateDID() *types.DIDPayload {
	info := new(types.DIDDoc)
	didjson.Unmarshal(didPayloadBytes, info)

	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     "create",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
		},
		DIDDoc: info,
	}

	privateKey1, _ := common.HexStringToBytes(PayloadPrivateKey)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadDeactivateDID(did, verifDid string) *types.DIDPayload {
	info := new(types.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     "create",
		},
		Payload: did,
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifDid,
		},
	}

	privateKey1, _ := common.HexStringToBytes(PayloadPrivateKey)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadUpdateDID() *types.DIDPayload {
	info := new(types.DIDDoc)
	didjson.Unmarshal(didPayloadBytes, info)

	return &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     "update",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: types.Proof{
			Type:               randomString(),
			VerificationMethod: randomString(),
			Signature:          randomString(),
		},
		DIDDoc: info,
	}
}

func randomString() string {
	a := make([]byte, 20)
	rand.Read(a)
	return common.BytesToHexString(a)
}

func getPayloadDIDInfo(id string, didDIDPayload string, docBytes []byte, privateKeyStr string) *types.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(types.DIDDoc)
	json.Unmarshal(docBytes, info)
	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary", //primary
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getCustomizedDIDDoc(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *types.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(types.DIDDoc)
	json.Unmarshal(docBytes, info)

	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" +
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getCustomizedDIDDocMultiSign(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *types.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(types.DIDDoc)
	json.Unmarshal(docBytes, info)

	//var Proofs []*types.Proof
	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		DIDDoc:  info,
	}
	proof1 := &types.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: id1 + "#primary", //"did:elastos:" +
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	p.Proof = *proof1
	return p
}

func (s *txValidatorTestSuite) TestGenrateTxFromRawTxStr() {
	rawTxStr := "0a000f656c6173746f732f6469642f312e30067570646174654038393666646533393565653539663265626330353464333" +
		"135643934383738663165636439346163333566663165373463653638653833346439353432653631fdd70c65794a705a434936496d" +
		"52705a44706c6247467a6447397a4f6d6c766455315457457449546d4e335a474a51656d49314f48425963473148516b524365484a4" +
		"e656d5a784d6d4d694c434a7764574a7361574e4c5a586b694f6c7437496d6c6b496a6f694933427961573168636e6b694c434a7764" +
		"574a7361574e4c5a586c4359584e6c4e5467694f6949794f54686a54474e7a566c7078556b3536566d354e646b5a55645849795a464" +
		"e68615852704d33567a555570425155685759305a5351564935517a556966563073496d46316447686c626e52705932463061573975" +
		"496a706249694e77636d6c7459584a35496c3073496e5a6c636d6c6d6157466962475644636d566b5a57353061574673496a70626579" +
		"4a705a43493649694e6c6247467a6447397a4c57466a5957526c62586b694c434a306558426c496a7062496b46776347787059324630" +
		"6157397555484a765a6d6c735a554e795a57526c626e5270595777694c434a485957316c5158427762476c6a5958527062323551636d" +
		"396d6157786c51334a6c5a47567564476c6862434973496c4e6c62475a51636d396a624746706257566b51334a6c5a47567564476c68" +
		"62434a644c434a7063334e315957356a5a555268644755694f6949794d4449774c54417a4c544577564441784f6a51334f6a453557694" +
		"973496d563463476c7959585270623235455958526c496a6f694d6a41794d4330774d7930794e5651774d546f304e7a6f784f566f694c4" +
		"34a6a636d566b5a5735306157467355335669616d566a6443493665794a6859335270623234694f694a4d5a574679626942466247467a" +
		"6447397a49474a354948427359586c70626d63675a3246745a584d67595764686157357a6443426d636d6c6c626d527a4969776959584" +
		"2776347466a6132466e5a534936496e526c5932677564485631625335305a584e304c6d466a5957526c62586b694c434a6863484230655" +
		"8426c496a6f695a5778686333527663324a796233647a5a5849694c434a705a47567564476c6d61575679496a6f695a577868633352766" +
		"37931685932466b5a573135496e3073496e42796232396d496a7037496e5a6c636d6c6d61574e6864476c76626b316c644768765a43493" +
		"649694e77636d6c7459584a354969776963326c6e626d463064584a6c496a6f69656d4e73516d784c6332347a536b633161324e4957455" +
		"24d4e445a4f613278454e6b706d656a68364d306458575456715a6e6443596a4a57564664504e564e5a4f57745a4d485a465a445242536e" +
		"4236646e684e61324666646c52686444687a4e6b633154324655596b7075587a5269615545696658307365794a705a43493649694e6c625" +
		"7467062434973496e5235634755694f6c7369516d467a61574e51636d396d6157786c51334a6c5a47567564476c6862434973496c4e6c62" +
		"475a51636d396a624746706257566b51334a6c5a47567564476c6862434a644c434a7063334e315957356a5a555268644755694f6949794" +
		"d4449774c5441324c544d77564449784f6a45794f6a453157694973496d563463476c7959585270623235455958526c496a6f694d6a4179" +
		"4e5330774e6930794f5651794d546f784d6a6f784e566f694c434a6a636d566b5a5735306157467355335669616d566a6443493665794a6" +
		"c6257467062434936496d7477643239765a484d784d4441785147647459576c734c6d4e7662534a394c434a77636d39765a6949366579" +
		"4a325a584a705a6d6c6a595852706232354e5a58526f623251694f69496a63484a706257467965534973496e4e705a323568644856795" +
		"a534936496d396a4f464e355a7a467354585a6962575a795a45493556455a6c596b6c5464314a485a55553556334e455957684c544442" +
		"46646b784852574e544c58497a636b6c434e446b3459585672646d4e5064465178575664366446566859545a33544455774d545259513" +
		"34e344f575a48566a4a6e496e31394c487369615751694f69496a5a3256755a4756794969776964486c775a53493657794a4359584e70" +
		"5931427962325a7062475644636d566b5a5735306157467349697769553256735a6c427962324e7359576c745a575244636d566b5a573" +
		"53061574673496c3073496d6c7a63335668626d4e6c524746305a534936496a49774d6a41744d4451744d6a64554d546b364d6a45364d7" +
		"a5661496977695a58687761584a6864476c76626b5268644755694f6949794d4449314c5441304c544932564445354f6a49784f6a4d315" +
		"7694973496d4e795a57526c626e52705957785464574a715a574e30496a7037496d646c626d526c63694936496d3168624755696653776" +
		"963484a76623259694f6e7369646d567961575a705932463061573975545756306147396b496a6f694933427961573168636e6b694c434" +
		"a7a6157647559585231636d55694f694a4b566c39424e6c4e5a5a454e776431465658326868656c4632516a4677597a526b55463975623" +
		"14a4f644731564f575634536a6c4e63474531564652744d6b67335448684a583064505347786f61303151515846304d57737752304e7a54" +
		"6b4e4d4e314a3658335270593256534c57743255534a3966537837496d6c6b496a6f6949323568625755694c434a306558426c496a706249" +
		"6b4a6863326c6a55484a765a6d6c735a554e795a57526c626e5270595777694c434a545a57786d55484a76593278686157316c5a454e795a" +
		"57526c626e5270595777695853776961584e7a64574675593256455958526c496a6f694d6a41794d4330774e4330794e3151784f546f794d" +
		"546f7a4e566f694c434a6c65484270636d463061573975524746305a534936496a49774d6a55744d4451744d6a5a554d546b364d6a4536" +
		"4d7a52614969776959334a6c5a47567564476c6862464e31596d706c593351694f6e7369626d46745a534936496b7451494664766232" +
		"527a496e3073496e42796232396d496a7037496e5a6c636d6c6d61574e6864476c76626b316c644768765a43493649694e77636d6c7459" +
		"584a354969776963326c6e626d463064584a6c496a6f69563139594e5870316245744a4f445a786545557452464e36645774354d335174" +
		"5a485a4b63327444625556314e6d39324c58683551316f77566c597764306870613142716445743459325978656c524754315257597a5a" +
		"555655747462336c326555467962456c34596b357a52464e504e5763696658307365794a705a43493649694e305a574e6f4c6e5231645" +
		"7307559574e685a47567465534973496e5235634755694f6c73695158427762476c6a5958527062323551636d396d6157786c51334a6c5" +
		"a47567564476c6862434973496b6468625756426348427361574e6864476c76626c427962325a7062475644636d566b5a57353061574673" +
		"49697769553256735a6c427962324e7359576c745a575244636d566b5a57353061574673496c3073496d6c7a63335668626d4e6c524746" +
		"305a534936496a49774d6a41744d4459744d4468554d5451364e444d364e445661496977695a58687761584a6864476c76626b52686447" +
		"55694f6949794d4449314c5441324c544133564445304f6a517a4f6a513157694973496d4e795a57526c626e52705957785464574a715a5" +
		"74e30496a7037496d466a64476c7662694936496b786c59584a754945567359584e3062334d67596e6b676347786865576c755a79426e59" +
		"57316c637942685a324670626e4e3049475a79615756755a484d694c434a686348427759574e725957646c496a6f696447566a61433530" +
		"645856744c6d466a5957526c62586b694c434a68634842306558426c496a6f695a5778686333527663324a796233647a5a5849694c434a" +
		"705a47567564476c6d61575679496a6f696447566a61433530645856744c6d466a5957526c62586b696653776963484a76623259694f6e7" +
		"369646d567961575a705932463061573975545756306147396b496a6f694933427961573168636e6b694c434a7a6157647559585231636" +
		"d55694f694a5953304e73626d5135616e426853566733546d4a43546b35496131397051306c54556e46506144646d53545a58554777324e" +
		"33644652475a685245356861586c685558646a61586f3557484977566a637964575a7963445259644868764d4856594e484a664d577733" +
		"4d7a424d537a464a5a794a3966563073496d563463476c795a584d694f6949794d4449314c54417a4c544577564441784f6a41314f6a4" +
		"13357694973496e42796232396d496a7037496d4e795a5746305a5751694f6949794d4449774c5441324c544d77564449784f6a45314f6a" +
		"453557694973496e4e705a323568644856795a565a686248566c496a6f6964545a35596d56535345354554473553563170445a574e3052" +
		"6b46584e4764735a57564a5754467256325a6c64334a3452485a615130704756325574656e6431595664725a44424b566d357a615846796" +
		"2544a35535864455232566964336c765955387963304a475230784e55557466536d63696658300e454344534173656370323536723136" +
		"6469643a656c6173746f733a696f754d53584b484e63776462507a6235387058706d4742444278724d7a66713263237072696d61727956" +
		"36654c7838576e35794a7246546e44666632585473494a5f7274452d636e5f6a69466c65555f734d494f456e364149714a3551425f79522" +
		"d734855484833756e4e6e63467978654d34564e4b7536384e3035326a706701810a31323334353637383930014d8c63e802bdee30f283a" +
		"12f807fadccefd2c144308cc6df9243f3f65dd2602900000000000002b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874d" +
		"f66a4ead0a300000000000000000000000067e75797a64c1f206b2f8bc6f80a5366eca28a23bbb037db964a231458d2d6ffd5ea18944c4" +
		"f90e63d547c5d3b9874df66a4ead0a3b8effa020000000000000000211dcb1c8a6b2c01b7901c25c56be4230d1f5ae5ca00000000014140" +
		"d155299c8b21063253724fb1412cd83901c8b51073975968086d94147e89c9d1f2b96a58fde1b36994a936759de813491000083343d62" +
		"e786d7040d9a989676c232103848390f4a687c247f4f662364c142a060ad10a03749178268decf9461b3c0fa5ac"
	data, err := common.HexStringToBytes(rawTxStr)
	if err != nil {
		fmt.Println("err", err)
		return

	}
	var tx types2.Transaction
	reader := bytes.NewReader(data)
	err2 := tx.Deserialize(reader)
	if err2 != nil {
		fmt.Println("err2", err2)
		return
	}
	s.validator.didParam.CustomIDFeeRate = 0
	s.validator.checkDIDTransaction(&tx, 0, 0)
}

//didDIDPayload must be create or update
func getDIDTx(id, didDIDPayload string, docBytes []byte, privateKeyStr string) *types2.Transaction {

	payloadDidInfo := getPayloadDIDInfo(id, didDIDPayload, docBytes, privateKeyStr)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

//didDIDPayload must be create or update
func getCustomizedDIDTx(id, didDIDPayload string, docBytes []byte, privateKeyStr string) *types2.Transaction {

	payloadDidInfo := getCustomizedDIDDoc(id, didDIDPayload, docBytes, privateKeyStr)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

func getDeactivateCustomizedDIDPayload(customizedDID, verifiacationDID string, privateKeyStr string) *types.DIDPayload {
	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     "",
		},
		Payload: customizedDID,
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifiacationDID + "#primary", //"did:elastos:" +
		},
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)

	publickey := base58.Decode("2BhWFosWHCKtBQpsPD3QZUY4NwCzavKdZEh6HfQDhciAY")
	pubkey, err := crypto.DecodePoint(publickey)
	fmt.Println(err)
	err = crypto.Verify(*pubkey, p.GetData(), sign)
	fmt.Println(err)
	return p
}

//didDIDPayload must be create or update
func getDeactivateCustomizedDIDTx(customizedDID, verifiacationDID, privateKeyStr string) *types2.Transaction {

	payloadDidInfo := getDeactivateCustomizedDIDPayload(customizedDID, verifiacationDID, privateKeyStr)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

//didDIDPayload must be create or update
func getCustomizedDIDTxMultSign(id1, id2, didDIDPayload string, docBytes []byte, privateKeyStr1, privateKeyStr2 string) *types2.Transaction {

	payloadDidInfo := getCustomizedDIDDocMultiSign(id1, id2, didDIDPayload, docBytes, privateKeyStr1, privateKeyStr2)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

func getDIDVerifiableCredentialPayload(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *types.DIDPayload {
	fmt.Println(" ---docBytes--- ", string(docBytes))
	info := new(types.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)

	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: types.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary",
		},
		CredentialDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//Verifiable credential payload must be create or update
func getIDVerifiableCredentialTx(id, didDIDPayload string, docBytes []byte, privateKeyStr string) *types2.Transaction {
	payloadDidInfo := getDIDVerifiableCredentialPayload(id, didDIDPayload, docBytes, privateKeyStr)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

//issuer.json SelfProclaimedCredential
func (s *txValidatorTestSuite) TestSelfProclaimedCredential() {
	s.SetupSuite()
	privateKey3Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id3 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

	//id3DocBytes
	tx3 := getDIDTx(id3, "create", id3DocByts, privateKey3Str)
	err3 := s.validator.checkDIDTransaction(tx3, 0, 0)
	s.NoError(err3)

	tx3_2 := getDIDTx(id3, "create", id2DocByts, privateKey3Str)
	err3_2 := s.validator.checkDIDTransaction(tx3_2, 0, 0)
	s.NoError(err3_2)

}

func (s *txValidatorTestSuite) TestCheckRegisterDID() {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte(id2), tx2,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	s.validator.didParam.CustomIDFeeRate = 0
	err2 := s.validator.checkDIDTransaction(tx1, 0, 0)
	s.NoError(err2)
}

func (s *txValidatorTestSuite) GetprivateKeyStr() string {
	privateKey1Str := "xprvA39XqfTw2FPEfpMJmM6jK1gzzRv8p1GYJS3DUEEbp1SibLrRyZzHijYTTvzy2a57Es8CBxs2xseMNoLC7nNGxsJY3nfCT3aUeozRQoy8vTH"
	privateKeyTemp := base58.Decode(privateKey1Str)
	privateKey := privateKeyTemp[46:78]
	base58PrivageKey := base58.Encode(privateKey)
	return base58PrivageKey
}

func (s *txValidatorTestSuite) TestCustomizedDID() {
	id1 := "did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj"
	privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ" //413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ
	tx1 := getDIDTx(id1, "create", id11DocByts, privateKey1Str)
	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte(id1), tx1,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	//examplercorp.id.json
	tx3 := getCustomizedDIDTx(id1, "create", customizedDIDDocSingleContrller, privateKey1Str)
	s.validator.didParam.CustomIDFeeRate = 0
	err3 := s.validator.checkCustomizedDID(tx3, 0, 0)
	s.NoError(err3)

	// todo fix me
}

//issuer.json SelfProclaimedCredential
func (s *txValidatorTestSuite) TestCustomizedDIDMultSign() {
	idUser1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	tx1 := getDIDTx(idUser1, "create", idUser1DocByts, privateKeyUser1Str)

	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte(idUser1), tx1,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	idUser2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	tx2 := getDIDTx(idUser2, "create", idUser2DocByts, privateKeyUser2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte(idUser2), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx2 := getCustomizedDIDTxMultSign(idUser1, idUser2, "create", customizedDIDDocBytes2,
		privateKeyUser1Str, privateKeyUser2Str)
	s.validator.didParam.CustomIDFeeRate = 0
	err := s.validator.checkCustomizedDID(CustomizedDIDTx2, 0, 0)
	s.NoError(err)

	// todo fix me

}

//self verifiable credential
func (s *txValidatorTestSuite) Test0DIDVerifiableCredentialTx() {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte(id2), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()
	//did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		DIDVerifableCredDocBytes, privateKey2Str)
	fmt.Println(verifableCredentialTx)
	err := s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.NoError(err)
}

//self verifiable credential
func (s *txValidatorTestSuite) TestRevokeVerifiableCredentialTx() {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte(id2), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()
	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		DIDVerifableCredDocBytes, privateKey2Str)
	fmt.Println(verifableCredentialTx)
	err := s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.NoError(err)

}

// one cotroller
func (s *txValidatorTestSuite) TestRevokeCustomizedDIDVerifiableCredentialTx() {
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"), tx1,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	batch3 := s.validator.Store.NewBatch()
	err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
		101, 123456)
	s.NoError(err3)
	batch3.Commit()

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"declare", customizedVerifableCredDocBytes, privateKey1Str)
	err := s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.NoError(err)

	credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	batch4 := s.validator.Store.NewBatch()
	err4 := s.validator.Store.PersistVerifiableCredentialTx(batch4, []byte(credentialID), verifableCredentialTx,
		100, 123456)
	s.NoError(err4)
	batch4.Commit()

	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", customizedVerifableCredDocBytes, privateKey2Str)
	err5 := s.validator.checkVerifiableCredential(verifableCredentialRevokeTx, 0, 0)
	s.NoError(err5)
}

// declare after real revoke
func (s *txValidatorTestSuite) TestRevokeBeforeRegisterVerifiableCredentialTx() {
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", customizedVerifableCredDocBytes, privateKey2Str)
	err := s.validator.checkVerifiableCredential(verifableCredentialRevokeTx, 0, 0)
	s.NoError(err)

	batch := s.validator.Store.NewBatch()
	err = s.validator.Store.PersistVerifiableCredentialTx(batch, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"), verifableCredentialRevokeTx,
		100, 123456)
	s.NoError(err)
	batch.Commit()

	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch1 := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch1, []byte("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"), tx1,
		100, 123456)
	s.NoError(err1)
	batch1.Commit()

	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	batch3 := s.validator.Store.NewBatch()
	err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
		101, 123456)
	s.NoError(err3)
	batch3.Commit()

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"declare", customizedVerifableCredDocBytes, privateKey1Str)
	err = s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.EqualError(err, "VerifiableCredential WRONG OPERATION ALREADY Revoked")
}

// declare after wrong revoke
func (s *txValidatorTestSuite) TestWrongRevokeBeforeRegisterVerifiableCredentialTx() {
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y",
		"revoke", customizedVerifableCredDocBytes, privateKey1Str)
	err5 := s.validator.checkVerifiableCredential(verifableCredentialRevokeTx, 0, 0)
	s.NoError(err5)

	batch := s.validator.Store.NewBatch()
	err := s.validator.Store.PersistVerifiableCredentialTx(batch, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"), verifableCredentialRevokeTx,
		100, 123456)
	s.NoError(err)
	batch.Commit()

	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey2Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch1 := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch1, []byte("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"), tx1,
		100, 123456)
	s.NoError(err1)
	batch1.Commit()

	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	batch3 := s.validator.Store.NewBatch()
	err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
		101, 123456)
	s.NoError(err3)
	batch3.Commit()

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"declare", customizedVerifableCredDocBytes, privateKey1Str)
	err = s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.NoError(err)
}

// revoke again
func (s *txValidatorTestSuite) TestDuplicatedRevokeVerifiableCredentialTx() {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", customizedVerifableCredDocBytes, privateKey2Str)
	err := s.validator.checkVerifiableCredential(verifableCredentialRevokeTx, 0, 0)
	s.NoError(err)

	batch := s.validator.Store.NewBatch()
	err = s.validator.Store.PersistVerifiableCredentialTx(batch, []byte("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"), verifableCredentialRevokeTx,
		100, 123456)
	s.NoError(err)
	batch.Commit()

	verifableCredentialRevokeTx2 := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", customizedVerifableCredDocBytes, privateKey2Str)
	err = s.validator.checkVerifiableCredential(verifableCredentialRevokeTx2, 0, 0)
	s.EqualError(err, "VerifiableCredential revoked again")
}

//more than  one cotroller
func (s *txValidatorTestSuite) TestCustomizedDIDVerifiableCredentialTx2() {
	//todo
	return
	s.SetupSuite()
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte("iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"), tx1,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte("ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx1 := getCustomizedDIDTxMultSign(id1, id2, "create", customizedDIDDocBytes2,
		privateKey1Str, privateKey2Str)
	customizedDID := "did:elastos:foobar"
	batch3 := s.validator.Store.NewBatch()
	err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
		101, 123456)
	s.NoError(err3)
	batch3.Commit()

	verifableCredentialTx := getCustomizedDIDVerifiableCredentialTxMultSign(id1, id2, "declare",
		customizedVerifableCredControllersDocBytes, privateKey1Str, privateKey2Str)
	err := s.validator.checkVerifiableCredential(verifableCredentialTx, 0, 0)
	s.NoError(err)
}

func (s *txValidatorTestSuite) TestDeactivateCustomizedDIDTX() {
	//todo
	//////////////////////////////
	//id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"

	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)

	batch := s.validator.Store.NewBatch()
	err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte(id1), tx1,
		100, 123456)
	s.NoError(err1)
	batch.Commit()

	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getDIDTx(id2, "create", id2DocByts, privateKey2Str)
	batch2 := s.validator.Store.NewBatch()
	err2 := s.validator.Store.PersistRegisterDIDTx(batch2, []byte(id2), tx2,
		100, 123456)
	s.NoError(err2)
	batch2.Commit()

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	batch3 := s.validator.Store.NewBatch()
	err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
		101, 123456)
	s.NoError(err3)
	batch3.Commit()
	///////////////////////
	//customizedDID
	//id1 is verificationmethod did
	//privateKey1Str outter proof sign(not for doc sign)
	txDeactivate := getDeactivateCustomizedDIDTx(customizedDID, id1, privateKey1Str)
	//Deactive did  have no
	err := s.validator.checkDeactivateDID(txDeactivate, 0, 0)
	s.NoError(err)

}

//customized did  have more than one controller
//this customized did send VerifiableCredentialTx
func getCustomizedDIDVerifiableCredentialTxMultSign(id1, id2, didDIDPayload string, docBytes []byte, privateKeyStr1, privateKeyStr2 string) *types2.Transaction {

	payloadDidInfo := getCustomizedDIDVerifiableCredPayloadContollers(id1, id2, didDIDPayload, docBytes, privateKeyStr1, privateKeyStr2)
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = payloadDidInfo
	return txn
}

// more than one controllers
func getCustomizedDIDVerifiableCredPayloadContollers(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *types.DIDPayload {
	info := new(types.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)
	fmt.Println("getCustomizedDIDDocMultiSign " + string(docBytes))

	//var Proofs []*types.Proof
	p := &types.DIDPayload{
		Header: types.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload:       base64url.EncodeToString(docBytes),
		CredentialDoc: info,
	}
	proof1 := &types.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: "did:elastos:" + id1 + "#primary",
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	//Proofs = append(Proofs, proof1)

	//proof2 := &types.Proof{
	//	Type:               "ECDSAsecp256r1",
	//	VerificationMethod: "did:elastos:" + id2 + "#primary",
	//}
	//privateKey2 := base58.Decode(privateKeyStr2)
	//sign2, _ := crypto.Sign(privateKey2, p.GetData())
	//proof2.Signature = base64url.EncodeToString(sign2)
	//Proofs = append(Proofs, proof2)

	p.Proof = *proof1
	return p
}

func (s *txValidatorTestSuite) TestHeaderPayloadDIDTX() {
	fmt.Println("TestHeaderPayloadDIDTX begin")

	operation := new(types.DIDPayload)
	json.Unmarshal(headerPayloadByts, operation)
	fmt.Printf("%+v \n", *operation)

	decodePayload, err := base64url.DecodeString(operation.Payload)
	s.NoError(err)

	info := new(types.DIDDoc)
	json.Unmarshal(decodePayload, info)
	operation.DIDDoc = info
	txn := new(types2.Transaction)
	txn.TxType = types.DIDOperation
	txn.Payload = operation
	s.validator.didParam.CustomIDFeeRate = 0
	err2 := s.validator.checkDIDTransaction(txn, 0, 0)
	s.NoError(err2)
	fmt.Println("TestHeaderPayloadDIDTX end")
}
