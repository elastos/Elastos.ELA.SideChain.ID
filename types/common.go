package types

import (
	"io/ioutil"
	"strings"
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
