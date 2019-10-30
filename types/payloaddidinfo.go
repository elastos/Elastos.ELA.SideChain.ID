package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/elastos/Elastos.ELA.SideChain.ID/types/base64url"
)

const DIDInfoVersion = 0x00

// header of DID transaction payload
type DIDHeaderInfo struct {
	Specification string `json:"specification"`
	Operation     string `json"operation"`
}

func (d *DIDHeaderInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Specification); err != nil {
		return errors.New("[DIDHeaderInfo], Specification serialize failed.")
	}

	if err := common.WriteVarString(w, d.Operation); err != nil {
		return errors.New("[DIDHeaderInfo], Operation serialize failed.")
	}

	return nil
}

func (d *DIDHeaderInfo) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Specification, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDHeaderInfo], Specification deserialize failed.")
	}

	d.Operation, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDHeaderInfo], Operation deserialize failed.")
	}

	return nil
}

// proof of DID transaction payload
type DIDProofInfo struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}

func (d *DIDProofInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Type); err != nil {
		return errors.New("[DIDProofInfo], Type serialize failed.")
	}

	if err := common.WriteVarString(w, d.VerificationMethod); err != nil {
		return errors.New("[DIDProofInfo], VerificationMethod serialize failed.")
	}

	if err := common.WriteVarString(w, d.Signature); err != nil {
		return errors.New("[DIDProofInfo], Signature serialize failed.")
	}
	return nil
}

func (d *DIDProofInfo) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Type, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], Type deserialize failed.")
	}

	d.VerificationMethod, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], VerificationMethod deserialize failed.")
	}

	d.Signature, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], Signature deserialize failed.")
	}
	return nil
}

// public keys of payload in DID transaction payload
type DIDPublicKeyInfo struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

func (p *DIDPublicKeyInfo) Serialize(w io.Writer, version byte) error {

	if err := common.WriteVarString(w, p.ID); err != nil {
		return errors.New("[DIDPublicKeyInfo], ID serialize failed.")
	}
	if err := common.WriteVarString(w, p.Type); err != nil {
		return errors.New("[DIDPublicKeyInfo], Type serialize failed.")
	}
	if err := common.WriteVarString(w, p.Controller); err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller serialize failed.")
	}
	if err := common.WriteVarString(w, p.PublicKeyBase58); err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 serialize failed.")
	}

	return nil
}

func (p *DIDPublicKeyInfo) Deserialize(r io.Reader, version byte) error {
	id, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], ID deserialize failed")
	}
	p.ID = id

	typePkInfo, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Type deserialize failed")
	}
	p.Type = typePkInfo

	controller, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller deserialize failed")
	}
	p.Controller = controller

	pkBase58, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 deserialize failed")
	}
	p.PublicKeyBase58 = pkBase58

	return nil
}

// payload in DID transaction payload
type DIDPayloadInfo struct {
	ID             string             `json:"id"`
	PublicKey      []DIDPublicKeyInfo `json:"publicKey"`
	Authentication []interface{}      `json:"authentication"`
	Authorization  []interface{}      `json:"authorization"`
	Expires        string             `json:expires`
}

// payload of DID transaction
type PayloadDIDInfo struct {
	Header  DIDHeaderInfo `json:"header"`
	Payload string        `json:"payload"`
	Proof   DIDProofInfo  `json:"proof"`

	PayloadInfo *DIDPayloadInfo
}

func (p *PayloadDIDInfo) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := p.Header.Serialize(buf, version); err != nil {
		return nil
	}
	if err := common.WriteVarString(buf, p.Payload); err != nil {
		return nil
	}
	return buf.Bytes()
}

func (p *PayloadDIDInfo) Serialize(w io.Writer, version byte) error {
	if err := p.Header.Serialize(w, version); err != nil {
		return errors.New("[PayloadDIDInfo], Header serialize failed," + err.Error())
	}

	if err := common.WriteVarString(w, p.Payload); err != nil {
		return errors.New("[PayloadDIDInfo], Payload serialize failed")
	}

	if err := p.Proof.Serialize(w, version); err != nil {
		return errors.New("[PayloadDIDInfo], Proof serialize failed," + err.Error())
	}

	return nil
}

func (p *PayloadDIDInfo) Deserialize(r io.Reader, version byte) error {
	if err := p.Header.Deserialize(r, version); err != nil {
		return errors.New("[DIDInfo], Header deserialize failed" + err.Error())
	}

	payload, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDInfo], payload deserialize failed")
	}
	p.Payload = payload

	if err := p.Proof.Deserialize(r, version); err != nil {
		return errors.New("[DIDInfo], Proof deserialize failed," + err.Error())
	}

	// get DIDPayloadInfo from payload data
	pBytes, err := base64url.DecodeString(p.Payload)
	if err != nil {
		return errors.New("[DIDInfo], payload decode failed")
	}
	payloadInfo := new(DIDPayloadInfo)
	if err := json.Unmarshal(pBytes, payloadInfo); err != nil {
		return errors.New("[DIDInfo], payload unmarshal failed")
	}
	p.PayloadInfo = payloadInfo
	return nil
}

func (p *PayloadDIDInfo) GetData() []byte {
	dataString := p.Header.Specification + p.Header.Operation + p.Payload
	return []byte(dataString)
}
