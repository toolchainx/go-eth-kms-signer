package sign

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"math/big"
	"os"
	"testing"
)

var typedData = apitypes.TypedData{
	Domain: apitypes.TypedDataDomain{
		Name:              "Snapshot Message",
		Version:           "4",
		ChainId:           (*math.HexOrDecimal256)(big.NewInt(1)),
		VerifyingContract: "0x0000000000000000000000000000000000000000",
	},
	Types: apitypes.Types{
		"coupon": []apitypes.Type{
			{Name: "authorizedMember", Type: "address"},
			{Name: "amount", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
		},
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
	},
	PrimaryType: "coupon",
	Message: apitypes.TypedDataMessage{
		"authorizedMember": "0xa9f01aaD34F2aF948F55612d06E51ae46ee08Bd4",
		"amount":           "100",
		"nonce":            "1",
	},
}

func TestGcpKmsSigner_SignTypedData(t *testing.T) {
	type fields struct {
		KeyVersionName string
		Address        string
	}
	type args struct {
		typedData apitypes.TypedData
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantSig []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "Test SignTypedData",
			fields: fields{
				KeyVersionName: os.Getenv("GCP_KMS_KEY_VERSION_NAME"),
				Address:        os.Getenv("GCP_KMS_ETH_WALLET_ADDRESS"),
			},
			args: args{
				typedData: typedData,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := NewGcpKmsSigner(tt.fields.Address, tt.fields.KeyVersionName)
			if err != nil {
				t.Errorf("NewGcpKmsSigner() error = %v", err)
				return
			}
			gotSig, err := k.SignTypedData(tt.args.typedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignTypedData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("SignTypedData() gotSig = %v", hexutil.Encode(gotSig))

			hash, err := EncodeForSigning(tt.args.typedData)
			if err != nil {
				t.Errorf("EncodeForSigning() error = %v", err)
				return
			}
			verifySig := VerifySig(tt.fields.Address, hexutil.Encode(gotSig), hash.Bytes())
			if !verifySig {
				t.Errorf("sig verify failed")
				return
			}
		})
	}
}

func TestWallet_SignTypedData(t *testing.T) {
	type fields struct {
		PrivateKey string
		Address    string
	}
	type args struct {
		typedData apitypes.TypedData
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantSig []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test wallet signer",
			fields: fields{
				PrivateKey: os.Getenv("ETH_WALLET_PRIVATE_KEY"),
				Address:    os.Getenv("ETH_WALLET_ADDRESS"),
			},
			args: args{
				typedData: typedData,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewWallet(tt.fields.Address, tt.fields.PrivateKey)
			if err != nil {
				t.Errorf("New Wallet error: %v", err)
			}
			gotSig, err := signer.SignTypedData(tt.args.typedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignTypedData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("SignTypedData() gotSig = %v", hexutil.Encode(gotSig))

			hash, err := EncodeForSigning(tt.args.typedData)
			if err != nil {
				t.Errorf("EncodeForSigning() error = %v", err)
				return
			}
			verifySig := VerifySig(tt.fields.Address, hexutil.Encode(gotSig), hash.Bytes())
			if !verifySig {
				t.Errorf("sig verify failed")
				return
			}
		})
	}
}
