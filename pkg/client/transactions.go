package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/wavesplatform/gowaves/pkg/crypto"
	"github.com/wavesplatform/gowaves/pkg/proto"
	"net/http"
)

type Transactions struct {
	options Options
}

// Creates new transaction api section
func NewTransactions(options Options) *Transactions {
	return &Transactions{
		options: options,
	}
}

// Get transaction that is in the UTX
func (a *Transactions) UnconfirmedInfo(ctx context.Context, id crypto.Digest) (proto.Transaction, *Response, error) {
	url, err := joinUrl(a.options.BaseUrl, fmt.Sprintf("/transactions/unconfirmed/info/%s", id.String()))
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	buf := new(bytes.Buffer)
	buf.WriteRune('[')
	response, err := doHttp(ctx, a.options, req, buf)
	if err != nil {
		return nil, response, err
	}
	buf.WriteRune(']')
	out := TransactionsField{}
	err = json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		return nil, response, &ParseError{Err: err}
	}

	if len(out) == 0 {
		return nil, response, errors.New("invalid transaction")
	}

	return out[0], response, nil
}

// Get the number of unconfirmed transactions in the UTX pool
func (a *Transactions) UnconfirmedSize(ctx context.Context) (uint64, *Response, error) {
	url, err := joinUrl(a.options.BaseUrl, "/transactions/unconfirmed/size")
	if err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return 0, nil, err
	}

	out := make(map[string]uint64)
	response, err := doHttp(ctx, a.options, req, &out)
	if err != nil {
		return 0, response, err
	}

	return out["size"], response, nil
}

// Get the number of unconfirmed transactions in the UTX pool
func (a *Transactions) Unconfirmed(ctx context.Context) ([]proto.Transaction, *Response, error) {
	url, err := joinUrl(a.options.BaseUrl, "/transactions/unconfirmed")
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	out := TransactionsField{}
	response, err := doHttp(ctx, a.options, req, &out)
	if err != nil {
		return nil, response, err
	}

	return out, response, nil
}

type TransactionTypeVersion struct {
	Type    proto.TransactionType `json:"type"`
	Version byte                  `json:"version,omitempty"`
}

// Get transaction info
func (a *Transactions) Info(ctx context.Context, id crypto.Digest) (proto.Transaction, *Response, error) {
	url, err := joinUrl(a.options.BaseUrl, fmt.Sprintf("/transactions/info/%s", id.String()))
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	buf := new(bytes.Buffer)
	buf.WriteRune('[')
	response, err := doHttp(ctx, a.options, req, buf)
	if err != nil {
		return nil, response, err
	}
	buf.WriteRune(']')
	out := TransactionsField{}
	err = json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		return nil, response, &ParseError{Err: err}
	}

	if len(out) == 0 {
		return nil, response, errors.New("invalid transaction ")
	}

	return out[0], response, nil
}

func (a *Transactions) Broadcast(ctx context.Context, tx proto.Transaction) (interface{}, *Response, error) {
	bts, err := json.Marshal(tx)
	if err != nil {
		return nil, nil, err
	}

	url, err := joinUrl(a.options.BaseUrl, "/transactions/broadcast")
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(
		"POST",
		url.String(),
		bytes.NewReader(bts))

	if err != nil {
		return nil, nil, err
	}

	out := new(interface{})
	response, err := doHttp(ctx, a.options, req, out)
	if err != nil {
		return nil, response, err
	}

	return out, response, nil
}

// Guess transaction from type and version
func GuessTransactionType(t *TransactionTypeVersion) (proto.Transaction, error) {
	var out proto.Transaction
	switch t.Type {
	case proto.GenesisTransaction: // 1
		out = &proto.Genesis{}
	case proto.PaymentTransaction: // 2
		out = &proto.Payment{}
	case proto.IssueTransaction: // 3
		out = &proto.IssueV1{}
	case proto.TransferTransaction: // 4
		if t.Version == 1 {
			out = &proto.TransferV1{}
		} else {
			out = &proto.TransferV2{}
		}
	case proto.ReissueTransaction: // 5
		out = &proto.ReissueV1{}
	case proto.BurnTransaction: // 6
		out = &proto.BurnV1{}
	case proto.ExchangeTransaction: // 7
		out = &proto.ExchangeV1{}
	case proto.LeaseTransaction: // 8
		out = &proto.LeaseV1{}
	case proto.LeaseCancelTransaction: // 9
		out = &proto.LeaseCancelV1{}
	case proto.CreateAliasTransaction: // 10
		out = &proto.CreateAliasV1{}
	case proto.MassTransferTransaction: // 11
		out = &proto.MassTransferV1{}
	case proto.DataTransaction: // 12
		out = &proto.DataV1{}
	case proto.SetScriptTransaction: // 13
		out = &proto.SetScriptV1{}
	case proto.SponsorshipTransaction: // 14
		out = &proto.SponsorshipV1{}
	default:
		out = &proto.Empty{}
	}
	if out == nil {
		return nil, errors.Errorf("unknown transaction type %d version %d", t.Type, t.Version)
	}
	return out, nil
}

// Guess transaction from type and version
func GuessTransactionTypeSingle(t *TransactionTypeVersion) (proto.Transaction, error) {
	var out proto.Transaction
	switch t.Type {
	case proto.TransferTransaction: // 4
		if t.Version == 1 {
			out = &proto.TransferV1{}
		} else if t.Version == 2 {
			out = &proto.TransferV2{}
		} else {
			out = &proto.Empty{}
		}
	default:
		out = &proto.Empty{}
	}
	return out, nil
}

// Get list of transactions where specified address has been involved
func (a *Transactions) Address(ctx context.Context, address proto.Address, limit uint) ([]proto.Transaction, *Response, error) {
	url, err := joinUrl(a.options.BaseUrl, fmt.Sprintf("/transactions/address/%s/limit/%d", address.String(), limit))
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	buf := new(bytes.Buffer)
	response, err := doHttp(ctx, a.options, req, buf)
	if err != nil {
		return nil, response, err
	}

	res := gjson.Parse(buf.String()).Array()[0]
	out := TransactionsField{}
	err = json.Unmarshal([]byte(res.String()), &out)
	if err != nil {
		return nil, response, &ParseError{Err: err}
	}

	if len(out) == 0 {
		return nil, response, errors.New("invalid transaction ")
	}

	return out, response, nil
}

type Fee struct {
	FeeAmount  int64               `json:"feeAmount,omitempty"`
	FeeAssetID proto.OptionalAsset `json:"feeAssetId,omitempty"`
}

func (a *Transactions) CalculateFee(ctx context.Context, tx proto.Transaction) (*Fee, *Response, error) {
	bts, err := json.Marshal(tx)
	if err != nil {
		return nil, nil, err
	}

	url, err := joinUrl(a.options.BaseUrl, "/transactions/calculateFee")
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(
		"POST",
		url.String(),
		bytes.NewReader(bts))

	if err != nil {
		return nil, nil, err
	}

	out := new(Fee)
	response, err := doHttp(ctx, a.options, req, out)
	if err != nil {
		return nil, response, err
	}

	return out, response, nil
}

type TransactionAlis struct {
	tx proto.Transaction
}

func (b *TransactionAlis) UnmarshalJSON(data []byte) error {
	var tt = &TransactionTypeVersion{}
	err := json.Unmarshal(data, tt)
	if err != nil {
		return err
	}

	realType, err := GuessTransactionTypeSingle(tt)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, realType)
	if err != nil {
		return err
	}
	b.tx = realType
	return nil
}

func (a *Transactions) Sign(ctx context.Context, tx proto.Transaction) (proto.Transaction, *Response, error) {
	bts, err := json.Marshal(tx)
	if err != nil {
		return nil, nil, err
	}

	url, err := joinUrl(a.options.BaseUrl, "/transactions/sign")
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest(
		"POST",
		url.String(),
		bytes.NewReader(bts))
	req.Header.Set("X-API-Key", a.options.ApiKey)

	if err != nil {
		return nil, nil, err
	}

	var out = &TransactionAlis{}
	response, err := doHttp(ctx, a.options, req, out)
	if err != nil {
		return nil, response, err
	}

	return out.tx, response, nil
}
