package proto

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"github.com/wavesplatform/gowaves/pkg/crypto"
)

//TransactionType
type TransactionType byte

//All transaction types supported.
const (
	GenesisTransaction TransactionType = iota + 1
	PaymentTransaction
	IssueTransaction
	TransferTransaction
	ReissueTransaction
	BurnTransaction
	ExchangeTransaction
	LeaseTransaction
	LeaseCancelTransaction
	CreateAliasTransaction
	MassTransferTransaction
	DataTransaction
	SetScriptTransaction
	SponsorshipTransaction
)

const (
	maxAttachmentLengthBytes = 140
	maxDescriptionLen        = 1000
	maxAssetNameLen          = 16
	minAssetNameLen          = 4
	maxDecimals              = 8

	genesisBodyLen            = 1 + 8 + AddressSize + 8
	paymentBodyLen            = 1 + 8 + crypto.PublicKeySize + AddressSize + 8 + 8
	issueV1FixedBodyLen       = 1 + crypto.PublicKeySize + 2 + 2 + 8 + 1 + 1 + 8 + 8
	issueV1MinBodyLen         = issueV1FixedBodyLen + 4 // 4 because of the shortest allowed Asset name of 4 bytes
	issueV1MinLen             = 1 + crypto.SignatureSize + issueV1MinBodyLen
	issueV2FixedBodyLen       = 1 + 1 + 1 + crypto.PublicKeySize + 2 + 2 + 8 + 1 + 1 + 8 + 8 + 1
	issueV2MinBodyLen         = issueV2FixedBodyLen + 4 // 4 because of the shortest allowed Asset name of 4 bytes
	issueV2MinLen             = 1 + issueV2MinBodyLen + proofsMinLen
	transferLen               = crypto.PublicKeySize + 1 + 1 + 8 + 8 + 8 + 2
	transferV1FixedBodyLen    = 1 + transferLen
	transferV1MinLen          = 1 + crypto.SignatureSize + transferV1FixedBodyLen
	transferV2FixedBodyLen    = 1 + 1 + transferLen
	transferV2MinLen          = 1 + transferV2FixedBodyLen + proofsMinLen
	reissueLen                = crypto.PublicKeySize + crypto.DigestSize + 8 + 1 + 8 + 8
	reissueV1BodyLen          = 1 + reissueLen
	reissueV1MinLen           = 1 + crypto.SignatureSize + reissueV1BodyLen
	reissueV2BodyLen          = 3 + reissueLen
	reissueV2MinLen           = 1 + reissueV2BodyLen + proofsMinLen
	burnLen                   = crypto.PublicKeySize + crypto.DigestSize + 8 + 8 + 8
	burnV1BodyLen             = 1 + burnLen
	burnV1Len                 = burnV1BodyLen + crypto.SignatureSize
	burnV2BodyLen             = 1 + 1 + 1 + burnLen
	burnV2Len                 = 1 + burnV2BodyLen + proofsMinLen
	exchangeV1FixedBodyLen    = 1 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8
	exchangeV1MinLen          = exchangeV1FixedBodyLen + orderV1MinLen + orderV1MinLen + crypto.SignatureSize
	exchangeV2FixedBodyLen    = 1 + 1 + 1 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8
	exchangeV2MinLen          = exchangeV2FixedBodyLen + orderV2MinLen + orderV2MinLen + proofsMinLen
	leaseLen                  = crypto.PublicKeySize + 8 + 8 + 8
	leaseV1BodyLen            = 1 + leaseLen
	leaseV1MinLen             = leaseV1BodyLen + crypto.SignatureSize
	leaseV2BodyLen            = 1 + 1 + 1 + leaseLen
	leaseV2MinLen             = leaseV2BodyLen + proofsMinLen
	leaseCancelLen            = crypto.PublicKeySize + 8 + 8 + crypto.DigestSize
	leaseCancelV1BodyLen      = 1 + leaseCancelLen
	leaseCancelV1MinLen       = leaseCancelV1BodyLen + crypto.SignatureSize
	leaseCancelV2BodyLen      = 1 + 1 + 1 + leaseCancelLen
	leaseCancelV2MinLen       = 1 + leaseCancelV2BodyLen + proofsMinLen
	createAliasLen            = crypto.PublicKeySize + 2 + 8 + 8 + aliasFixedSize
	createAliasV1FixedBodyLen = 1 + createAliasLen
	createAliasV1MinLen       = createAliasV1FixedBodyLen + crypto.SignatureSize
	createAliasV2FixedBodyLen = 1 + 1 + createAliasLen
	createAliasV2MinLen       = 1 + createAliasV2FixedBodyLen + proofsMinLen
	massTransferEntryLen      = 8
	massTransferV1FixedLen    = 1 + 1 + crypto.PublicKeySize + 1 + 2 + 8 + 8 + 2
	massTransferV1MinLen      = massTransferV1FixedLen + proofsMinLen
	dataV1FixedBodyLen        = 1 + 1 + crypto.PublicKeySize + 2 + 8 + 8
	dataV1MinLen              = dataV1FixedBodyLen + proofsMinLen
	setScriptV1FixedBodyLen   = 1 + 1 + 1 + crypto.PublicKeySize + 1 + 8 + 8
	setScriptV1MinLen         = 1 + setScriptV1FixedBodyLen + proofsMinLen
	sponsorshipV1BodyLen      = 1 + 1 + crypto.PublicKeySize + crypto.DigestSize + 8 + 8 + 8
	sponsorshipV1MinLen       = 1 + 1 + 1 + sponsorshipV1BodyLen + proofsMinLen
)

type Transaction interface {
	Transaction()
	GetID() []byte
}

//Genesis is a transaction used to initial balances distribution. This transactions allowed only in the first block.
type Genesis struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Signature `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	Timestamp uint64            `json:"timestamp"`
	Recipient Address           `json:"recipient"`
	Amount    uint64            `json:"amount"`
}

func (Genesis) Transaction() {}
func (tx Genesis) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedGenesis returns a new unsigned Genesis transaction. Actually Genesis transaction could not be signed.
//That is why it doesn't implement Sing method. Instead it has GenerateSigID method, which calculates ID and uses it also as a signature.
func NewUnsignedGenesis(recipient Address, amount, timestamp uint64) (*Genesis, error) {
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if ok, err := recipient.Validate(); !ok {
		return nil, errors.Wrapf(err, "invalid recipient address '%s'", recipient.String())
	}
	return &Genesis{Type: GenesisTransaction, Version: 1, Timestamp: timestamp, Recipient: recipient, Amount: amount}, nil
}

func (tx *Genesis) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, genesisBodyLen)
	buf[0] = byte(tx.Type)
	binary.BigEndian.PutUint64(buf[1:], tx.Timestamp)
	copy(buf[9:], tx.Recipient[:])
	binary.BigEndian.PutUint64(buf[9+AddressSize:], tx.Amount)
	return buf, nil
}

func (tx *Genesis) bodyUnmarshalBinary(data []byte) error {
	tx.Type = TransactionType(data[0])
	tx.Version = 1
	if tx.Type != GenesisTransaction {
		return errors.Errorf("unexpected transaction type %d for Genesis transaction", tx.Type)
	}
	data = data[1:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	copy(tx.Recipient[:], data[:AddressSize])
	data = data[AddressSize:]
	tx.Amount = binary.BigEndian.Uint64(data)
	return nil
}

//GenerateSigID calculates hash of the transaction and use it as an ID. Also doubled hash is used as a signature.
func (tx *Genesis) GenerateSigID() error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to generate signature of Genesis transaction")
	}
	d := make([]byte, len(b)+3)
	copy(d[3:], b)
	h, err := crypto.FastHash(d)
	if err != nil {
		return errors.Wrap(err, "failed to generate signature of Genesis transaction")
	}
	var s crypto.Signature
	copy(s[0:], h[:])
	copy(s[crypto.DigestSize:], h[:])
	tx.ID = &s
	tx.Signature = &s
	return nil
}

//MarshalBinary writes transaction bytes to slice of bytes.
func (tx *Genesis) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal Genesis transaction to bytes")
	}
	return b, nil
}

//UnmarshalBinary reads transaction values from the slice of bytes.
func (tx *Genesis) UnmarshalBinary(data []byte) error {
	if l := len(data); l != genesisBodyLen {
		return errors.Errorf("incorrect data lenght for Genesis transaction, expected %d, received %d", genesisBodyLen, l)
	}
	if data[0] != byte(GenesisTransaction) {
		return errors.Errorf("incorrect transaction type %d for Genesis transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Genesis transaction from bytes")
	}
	err = tx.GenerateSigID()
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Genesis transaction from bytes")
	}
	return nil
}

//Payment transaction is deprecated and can be used only for validation of blockchain.
type Payment struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version"`
	ID        *crypto.Signature `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	SenderPK  crypto.PublicKey  `json:"senderPublicKey"`
	Recipient Address           `json:"recipient"`
	Amount    uint64            `json:"amount"`
	Fee       uint64            `json:"fee"`
	Timestamp uint64            `json:"timestamp"`
}

func (Payment) Transaction() {}
func (tx Payment) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedPayment creates new Payment transaction with empty Signature and ID fields.
func NewUnsignedPayment(senderPK crypto.PublicKey, recipient Address, amount, fee, timestamp uint64) (*Payment, error) {
	if ok, err := recipient.Validate(); !ok {
		return nil, errors.Wrapf(err, "invalid recipient address '%s'", recipient.String())
	}
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &Payment{Type: PaymentTransaction, Version: 1, SenderPK: senderPK, Recipient: recipient, Amount: amount, Fee: fee, Timestamp: timestamp}, nil
}

func (tx *Payment) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, paymentBodyLen)
	buf[0] = byte(tx.Type)
	binary.BigEndian.PutUint64(buf[1:], tx.Timestamp)
	copy(buf[9:], tx.SenderPK[:])
	copy(buf[9+crypto.PublicKeySize:], tx.Recipient[:])
	binary.BigEndian.PutUint64(buf[9+crypto.PublicKeySize+AddressSize:], tx.Amount)
	binary.BigEndian.PutUint64(buf[17+crypto.PublicKeySize+AddressSize:], tx.Fee)
	return buf, nil

}

func (tx *Payment) bodyUnmarshalBinary(data []byte) error {
	tx.Type = TransactionType(data[0])
	tx.Version = 1
	if l := len(data); l != paymentBodyLen {
		return errors.Errorf("incorrect data size %d for Payment transaction, expected %d", l, paymentBodyLen)
	}
	if tx.Type != PaymentTransaction {
		return errors.Errorf("unexpected transaction type %d for Payment transaction", tx.Type)
	}
	data = data[1:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	copy(tx.Recipient[:], data[:AddressSize])
	data = data[AddressSize:]
	tx.Amount = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Fee = binary.BigEndian.Uint64(data)
	return nil
}

//Sign calculates transaction signature and set it as an ID.
func (tx *Payment) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign Payment transaction")
	}
	d := make([]byte, len(b)+3)
	copy(d[3:], b)
	s := crypto.Sign(secretKey, d)
	tx.ID = &s
	tx.Signature = &s
	return nil
}

//Verify checks that the Signature is valid for given public key.
func (tx *Payment) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify Payment transaction")
	}
	d := make([]byte, len(b)+3)
	copy(d[3:], b)
	return crypto.Verify(publicKey, *tx.Signature, d), nil
}

//MarshalBinary returns a bytes representation of Payment transaction.
func (tx *Payment) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {

	}
	buf := make([]byte, paymentBodyLen+crypto.SignatureSize)
	copy(buf, b)
	copy(buf[paymentBodyLen:], tx.Signature[:])
	return buf, nil
}

//UnmarshalBinary reads Payment transaction from its binary representation.
func (tx *Payment) UnmarshalBinary(data []byte) error {
	size := paymentBodyLen + crypto.SignatureSize
	if l := len(data); l != size {
		return errors.Errorf("not enough data for Payment transaction, expected %d, received %d", size, l)
	}
	if data[0] != byte(PaymentTransaction) {
		return errors.Errorf("incorrect transaction type %d for Payment transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data[:paymentBodyLen])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Payment transaction from bytes")
	}
	data = data[paymentBodyLen:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	tx.ID = &s
	return nil
}

//IssueV1 transaction is a transaction to issue new asset.
type IssueV1 struct {
	Type        TransactionType   `json:"type"`
	Version     byte              `json:"version,omitempty"`
	ID          *crypto.Digest    `json:"id,omitempty"`
	Signature   *crypto.Signature `json:"signature,omitempty"`
	SenderPK    crypto.PublicKey  `json:"senderPublicKey"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Quantity    uint64            `json:"quantity"`
	Decimals    byte              `json:"decimals"`
	Reissuable  bool              `json:"reissuable"`
	Timestamp   uint64            `json:"timestamp,omitempty"`
	Fee         uint64            `json:"fee"`
}

func (IssueV1) Transaction() {}
func (tx IssueV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedIssueV1 creates new IssueV1 transaction without signature and ID.
func NewUnsignedIssueV1(senderPK crypto.PublicKey, name, description string, quantity uint64, decimals byte, reissuable bool, timestamp, fee uint64) (*IssueV1, error) {
	if l := len(name); l < minAssetNameLen || l > maxAssetNameLen {
		return nil, errors.New("incorrect number of bytes in the asset's name")
	}
	if l := len(description); l > maxDescriptionLen {
		return nil, errors.New("incorrect number of bytes in the asset's description")
	}
	if quantity <= 0 {
		return nil, errors.New("quantity should be positive")
	}
	if decimals > maxDecimals {
		return nil, errors.Errorf("incorrect decimals, should be no more then %d", maxDecimals)
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &IssueV1{Type: IssueTransaction, Version: 1, SenderPK: senderPK, Name: name, Description: description, Quantity: quantity, Decimals: decimals, Reissuable: reissuable, Timestamp: timestamp, Fee: fee}, nil
}

func (tx *IssueV1) bodyMarshalBinary() ([]byte, error) {
	kl := crypto.PublicKeySize
	nl := len(tx.Name)
	dl := len(tx.Description)
	buf := make([]byte, issueV1FixedBodyLen+nl+dl)
	buf[0] = byte(tx.Type)
	copy(buf[1:], tx.SenderPK[:])
	PutStringWithUInt16Len(buf[1+kl:], tx.Name)
	PutStringWithUInt16Len(buf[3+kl+nl:], tx.Description)
	binary.BigEndian.PutUint64(buf[5+kl+nl+dl:], tx.Quantity)
	buf[13+kl+nl+dl] = tx.Decimals
	PutBool(buf[14+kl+nl+dl:], tx.Reissuable)
	binary.BigEndian.PutUint64(buf[15+kl+nl+dl:], tx.Fee)
	binary.BigEndian.PutUint64(buf[23+kl+nl+dl:], tx.Timestamp)
	return buf, nil
}

func (tx *IssueV1) bodyUnmarshalBinary(data []byte) error {
	tx.Type = TransactionType(data[0])
	tx.Version = 1
	if l := len(data); l < issueV1MinBodyLen {
		return errors.Errorf("not enough data for IssueV1 transaction %d, expected not less then %d", l, issueV1MinBodyLen)
	}
	if tx.Type != IssueTransaction {
		return errors.Errorf("unexpected transaction type %d for IssueV1 transaction", tx.Type)
	}
	data = data[1:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	var err error
	tx.Name, err = StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Name")
	}
	data = data[2+len(tx.Name):]
	tx.Description, err = StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Description")
	}
	data = data[2+len(tx.Description):]
	tx.Quantity = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Decimals = data[0]
	data = data[1:]
	tx.Reissuable, err = Bool(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Reissuable")
	}
	data = data[1:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//Sign uses secretKey to sing the transaction.
func (tx *IssueV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign IssueV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign IssueV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the signature of transaction is a valid signature for given public key.
func (tx *IssueV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of IssueV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves transaction's binary representation to slice of bytes.
func (tx *IssueV1) MarshalBinary() ([]byte, error) {
	sl := crypto.SignatureSize
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal IssueV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, 1+sl+bl)
	buf[0] = byte(tx.Type)
	copy(buf[1:], tx.Signature[:])
	copy(buf[1+sl:], b)
	return buf, nil
}

//UnmarshalBinary reads transaction from its binary representation.
func (tx *IssueV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < issueV1MinLen {
		return errors.Errorf("not enough data for IssueV1 transaction, expected not less then %d, received %d", issueV1MinLen, l)
	}
	if data[0] != byte(IssueTransaction) {
		return errors.Errorf("incorrect transaction type %d for IssueV1 transaction", data[0])
	}
	data = data[1:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	data = data[crypto.SignatureSize:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal IssueV1 transaction")
	}
	d, err := crypto.FastHash(data)
	if err != nil {
		return errors.Wrap(err, "failed to hash IssueV1 transaction")
	}
	tx.ID = &d
	return nil
}

// IssueV2 is a transaction to issue new asset, second version.
type IssueV2 struct {
	Type        TransactionType  `json:"type"`
	Version     byte             `json:"version"`
	ChainID     byte             `json:"-"`
	ID          *crypto.Digest   `json:"id,omitempty"`
	Proofs      *ProofsV1        `json:"proofs,omitempty"`
	SenderPK    crypto.PublicKey `json:"senderPublicKey"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Quantity    uint64           `json:"quantity"`
	Decimals    byte             `json:"decimals"`
	Reissuable  bool             `json:"reissuable"`
	Script      []byte           `json:"script"`
	Fee         uint64           `json:"fee"`
	Timestamp   uint64           `json:"timestamp,omitempty"`
}

func (IssueV2) Transaction() {}

//NewUnsignedIssueV2 creates a new IssueV2 transaction with empty Proofs.
func NewUnsignedIssueV2(chainID byte, senderPK crypto.PublicKey, name, description string, quantity uint64, decimals byte, reissuable bool, script []byte, timestamp, fee uint64) (*IssueV2, error) {
	if l := len(name); l < minAssetNameLen || l > maxAssetNameLen {
		return nil, errors.New("incorrect number of bytes in the asset's name")
	}
	if l := len(description); l > maxDescriptionLen {
		return nil, errors.New("incorrect number of bytes in the asset's description")
	}
	if quantity <= 0 {
		return nil, errors.New("quantity should be positive")
	}
	if decimals > maxDecimals {
		return nil, errors.Errorf("incorrect decimals, should be no more then %d", maxDecimals)
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &IssueV2{Type: IssueTransaction, Version: 2, ChainID: chainID, SenderPK: senderPK, Name: name, Description: description, Quantity: quantity, Decimals: decimals, Reissuable: reissuable, Script: script, Timestamp: timestamp, Fee: fee}, nil
}

//NonEmptyScript returns true if the script of the transaction is not empty, otherwise false.
func (tx *IssueV2) NonEmptyScript() bool {
	return len(tx.Script) != 0
}

func (tx *IssueV2) bodyMarshalBinary() ([]byte, error) {
	var p int
	nl := len(tx.Name)
	dl := len(tx.Description)
	sl := len(tx.Script)
	if sl > 0 {
		sl += 2
	}
	buf := make([]byte, issueV2FixedBodyLen+nl+dl+sl)
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	buf[2] = tx.ChainID
	p = 3
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	PutStringWithUInt16Len(buf[p:], tx.Name)
	p += 2 + nl
	PutStringWithUInt16Len(buf[p:], tx.Description)
	p += 2 + dl
	binary.BigEndian.PutUint64(buf[p:], tx.Quantity)
	p += 8
	buf[p] = tx.Decimals
	p++
	PutBool(buf[p:], tx.Reissuable)
	p++
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	p += 8
	PutBool(buf[p:], tx.NonEmptyScript())
	p++
	if tx.NonEmptyScript() {
		PutBytesWithUInt16Len(buf[p:], tx.Script)
	}
	return buf, nil
}

func (tx *IssueV2) bodyUnmarshalBinary(data []byte) error {
	const message = "failed to unmarshal field %q of IssueV2 transaction"
	if l := len(data); l < issueV2MinBodyLen {
		return errors.Errorf("not enough data for IssueV2 transaction %d, expected not less then %d", l, issueV2MinBodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != IssueTransaction {
		return errors.Errorf("unexpected transaction type %d for IssueV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	tx.ChainID = data[2]
	data = data[3:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	var err error
	tx.Name, err = StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrapf(err, message, "Name")
	}
	data = data[2+len(tx.Name):]
	tx.Description, err = StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrapf(err, message, "Description")
	}
	data = data[2+len(tx.Description):]
	tx.Quantity = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Decimals = data[0]
	data = data[1:]
	tx.Reissuable, err = Bool(data)
	if err != nil {
		return errors.Wrapf(err, message, "Reissuable")
	}
	data = data[1:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	p, err := Bool(data)
	if err != nil {
		return errors.Wrapf(err, message, "Script")
	}
	data = data[1:]
	if p {
		s, err := BytesWithUInt16Len(data)
		if err != nil {
			return errors.Wrapf(err, message, "Script")
		}
		tx.Script = s
	}
	return nil
}

//Sign calculates transaction signature using given secret key.
func (tx *IssueV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign IssueV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign IssueV2 transaction")
	}
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign IssueV2 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the transaction signature is valid for given public key.
func (tx *IssueV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of IssueV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary converts transaction to its binary representation.
func (tx *IssueV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal IssueV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal IssueV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal IssueV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	var p int
	buf[p] = 0
	p++
	copy(buf[p:], bb)
	p += bl
	copy(buf[p:], pb)
	return buf, nil
}

//UnmarshalBinary reads transaction from its binary representation.
func (tx *IssueV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < issueV2MinLen {
		return errors.Errorf("not enough data for IssueV2 transaction, expected not less then %d, received %d", issueV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d for IssueV2 transaction, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal IssueV2 transaction")
	}
	sl := len(tx.Script)
	if sl > 0 {
		sl += 2
	}
	bl := issueV2FixedBodyLen + len(tx.Name) + len(tx.Description) + sl
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal IssueV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal IssueV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type transfer struct {
	SenderPK    crypto.PublicKey `json:"senderPublicKey"`
	AmountAsset OptionalAsset    `json:"assetId"`
	FeeAsset    OptionalAsset    `json:"feeAssetId"`
	Timestamp   uint64           `json:"timestamp,omitempty"`
	Amount      uint64           `json:"amount"`
	Fee         uint64           `json:"fee"`
	Recipient   Recipient        `json:"recipient"`
	Attachment  Attachment       `json:"attachment,omitempty"`

	FeeAssetID OptionalAsset `json:"feeAsset,omitempty"`
	Sender     string        `json:"sender,omitempty"`
	Height     int64         `json:"height,omitempty"`
}

func newTransfer(senderPK crypto.PublicKey, amountAsset, feeAsset OptionalAsset, timestamp, amount, fee uint64, recipient Address, attachment string) (*transfer, error) {
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	if len(attachment) > maxAttachmentLengthBytes {
		return nil, errors.New("attachment too long")
	}
	if ok, err := recipient.Validate(); !ok {
		return nil, errors.Wrapf(err, "invalid recipient address '%s'", recipient.String())
	}
	return &transfer{SenderPK: senderPK, AmountAsset: amountAsset, FeeAsset: feeAsset, Timestamp: timestamp, Amount: amount, Fee: fee, Recipient: NewRecipientFromAddress(recipient), Attachment: Attachment(attachment)}, nil
}

func (tx *transfer) marshalBinary() ([]byte, error) {
	p := 0
	aal := 0
	if tx.AmountAsset.Present {
		aal += crypto.DigestSize
	}
	fal := 0
	if tx.FeeAsset.Present {
		fal += crypto.DigestSize
	}
	rb, err := tx.Recipient.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal transfer body")
	}
	rl := len(rb)
	atl := len(tx.Attachment)
	buf := make([]byte, transferLen+aal+fal+atl+rl)
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	aab, err := tx.AmountAsset.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal transfer body")
	}
	copy(buf[p:], aab)
	p += 1 + aal
	fab, err := tx.FeeAsset.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal transfer body")
	}
	copy(buf[p:], fab)
	p += 1 + fal
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Amount)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	copy(buf[p:], rb)
	p += rl
	PutStringWithUInt16Len(buf[p:], tx.Attachment.String())
	return buf, nil
}

func (tx *transfer) unmarshalBinary(data []byte) error {
	if l := len(data); l < transferLen {
		return errors.Errorf("%d bytes is not enough for transfer body, expected not less then %d bytes", l, transferLen)
	}
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	var err error
	err = tx.AmountAsset.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal transfer body from bytes")
	}
	data = data[1:]
	if tx.AmountAsset.Present {
		data = data[crypto.DigestSize:]
	}
	err = tx.FeeAsset.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal transfer body from bytes")
	}
	data = data[1:]
	if tx.FeeAsset.Present {
		data = data[crypto.DigestSize:]
	}
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Amount = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	err = tx.Recipient.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal transfer body from bytes")
	}
	data = data[tx.Recipient.len:]
	a, err := StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal transfer body from bytes")
	}
	tx.Attachment = Attachment(a)
	return nil
}

//TransferV1 transaction to transfer any token from one account to another. Version 1.
type TransferV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`

	Proofs *ProofsV1 `json:"proofs,omitempty"`
	transfer
}

func (TransferV1) Transaction() {}
func (tx TransferV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedTransferV1 creates new TransferV1 transaction without signature and ID.
func NewUnsignedTransferV1(senderPK crypto.PublicKey, amountAsset, feeAsset OptionalAsset, timestamp, amount, fee uint64, recipient Address, attachment string) (*TransferV1, error) {
	t, err := newTransfer(senderPK, amountAsset, feeAsset, timestamp, amount, fee, recipient, attachment)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TransferV1 transaction")
	}
	return &TransferV1{Type: TransferTransaction, Version: 1, transfer: *t}, nil
}

func (tx *TransferV1) bodyMarshalBinary() ([]byte, error) {
	b, err := tx.transfer.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal TransferV1 body")
	}
	buf := make([]byte, 1+len(b))
	buf[0] = byte(tx.Type)
	copy(buf[1:], b)
	return buf, nil
}

func (tx *TransferV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < transferV1FixedBodyLen {
		return errors.Errorf("%d bytes is not enough for TransferV1 transaction, expected not less then %d bytes", l, transferV1FixedBodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != TransferTransaction {
		return errors.Errorf("unexpected transaction type %d for TransferV1 transaction", tx.Type)
	}
	tx.Version = 1
	var t transfer
	err := t.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV1 body from bytes")
	}
	tx.transfer = t
	return nil
}

//Sign calculates a signature and a digest as an ID of the transaction.
func (tx *TransferV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign TransferV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign TransferV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify use given public key to verify that the signature is valid.
func (tx *TransferV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of TransferV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves transaction to its binary representation.
func (tx *TransferV1) MarshalBinary() ([]byte, error) {
	sl := crypto.SignatureSize
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal TransferV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, 1+sl+bl)
	buf[0] = byte(tx.Type)
	copy(buf[1:], tx.Signature[:])
	copy(buf[1+sl:], b)
	return buf, nil
}

//UnmarshalBinary reads transaction from its binary representation.
func (tx *TransferV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < transferV1MinLen {
		return errors.Errorf("not enough data for TransferV1 transaction, expected not less then %d, received %d", transferV1MinLen, l)
	}
	if data[0] != byte(TransferTransaction) {
		return errors.Errorf("incorrect transaction type %d for TransferV1 transaction", data[0])
	}
	data = data[1:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	data = data[crypto.SignatureSize:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV1 transaction")
	}
	d, err := crypto.FastHash(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV1 transaction")
	}
	tx.ID = &d
	return nil
}

//TransferV2 transaction to transfer any token from one account to another. Version 2.
type TransferV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	transfer
}

func (TransferV2) Transaction() {}
func (tx TransferV2) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedTransferV2 creates new TransferV2 transaction without proofs and ID.
func NewUnsignedTransferV2(senderPK crypto.PublicKey, amountAsset, feeAsset OptionalAsset, timestamp, amount, fee uint64, recipient Address, attachment string) (*TransferV2, error) {
	t, err := newTransfer(senderPK, amountAsset, feeAsset, timestamp, amount, fee, recipient, attachment)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TransferV2 transaction")
	}
	return &TransferV2{Type: TransferTransaction, Version: 2, transfer: *t}, nil
}

func (tx *TransferV2) BodyMarshalBinary() ([]byte, error) {
	b, err := tx.transfer.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal TransferV2 body")
	}
	buf := make([]byte, 2+len(b))
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	copy(buf[2:], b)
	return buf, nil
}

func (tx *TransferV2) BodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < transferV2FixedBodyLen {
		return errors.Errorf("%d bytes is not enough for TransferV2 transaction, expected not less then %d bytes", l, transferV2FixedBodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != TransferTransaction {
		return errors.Errorf("unexpected transaction type %d for TransferV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	if v := tx.Version; v != 2 {
		return errors.Errorf("unexpected version %d for TransferV2 transaction, expected 2", v)
	}
	var t transfer
	err := t.unmarshalBinary(data[2:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV2 body from bytes")
	}
	tx.transfer = t
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *TransferV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.BodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign TransferV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign TransferV2 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign TransferV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *TransferV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.BodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of TransferV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary writes TransferV2 transaction to its bytes representation.
func (tx *TransferV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.BodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal TransferV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal TransferV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal TransferV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads TransferV2 from its bytes representation.
func (tx *TransferV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < transferV2MinLen {
		return errors.Errorf("not enough data for TransferV2 transaction, expected not less then %d, received %d", transferV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.BodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV2 transaction from bytes")
	}
	aal := 0
	if tx.AmountAsset.Present {
		aal += crypto.DigestSize
	}
	fal := 0
	if tx.FeeAsset.Present {
		fal += crypto.DigestSize
	}
	atl := len(tx.Attachment)
	rl := tx.Recipient.len
	bl := transferV2FixedBodyLen + aal + fal + atl + rl
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal TransferV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type reissue struct {
	SenderPK   crypto.PublicKey `json:"senderPublicKey"`
	AssetID    crypto.Digest    `json:"assetId"`
	Quantity   uint64           `json:"quantity"`
	Reissuable bool             `json:"reissuable"`
	Timestamp  uint64           `json:"timestamp,omitempty"`
	Fee        uint64           `json:"fee"`
}

func newReissue(senderPK crypto.PublicKey, assetID crypto.Digest, quantity uint64, reissuable bool, timestamp, fee uint64) (*reissue, error) {
	if quantity <= 0 {
		return nil, errors.New("quantity should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &reissue{SenderPK: senderPK, AssetID: assetID, Quantity: quantity, Reissuable: reissuable, Timestamp: timestamp, Fee: fee}, nil
}

func (tx *reissue) marshalBinary() ([]byte, error) {
	p := 0
	buf := make([]byte, reissueLen)
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	copy(buf[p:], tx.AssetID[:])
	p += crypto.DigestSize
	binary.BigEndian.PutUint64(buf[p:], tx.Quantity)
	p += 8
	PutBool(buf[p:], tx.Reissuable)
	p++
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	return buf, nil
}

func (tx *reissue) unmarshalBinary(data []byte) error {
	if l := len(data); l < reissueLen {
		return errors.Errorf("%d bytes is not enough for reissue body, expected not less then %d bytes", l, reissueLen)
	}
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	copy(tx.AssetID[:], data[:crypto.DigestSize])
	data = data[crypto.DigestSize:]
	tx.Quantity = binary.BigEndian.Uint64(data)
	data = data[8:]
	var err error
	tx.Reissuable, err = Bool(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal Reissuable")
	}
	data = data[1:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//ReissueV1 is a transaction that allows to issue new amount of existing token, if it was issued as reissuable.
type ReissueV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	reissue
}

func (ReissueV1) Transaction() {}
func (tx ReissueV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedReissueV1 creates new ReissueV1 transaction without signature and ID.
func NewUnsignedReissueV1(senderPK crypto.PublicKey, assetID crypto.Digest, quantity uint64, reissuable bool, timestamp, fee uint64) (*ReissueV1, error) {
	r, err := newReissue(senderPK, assetID, quantity, reissuable, timestamp, fee)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ReissueV1 transaction")
	}
	return &ReissueV1{Type: ReissueTransaction, Version: 1, reissue: *r}, nil
}

func (tx *ReissueV1) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, reissueV1BodyLen)
	buf[0] = byte(tx.Type)
	b, err := tx.reissue.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ReissueV1 transaction to bytes")
	}
	copy(buf[1:], b)
	return buf, nil
}

func (tx *ReissueV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < reissueV1BodyLen {
		return errors.Errorf("not enough data for ReissueV1 transaction %d, expected not less then %d", l, reissueV1BodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != ReissueTransaction {
		return errors.Errorf("unexpected transaction type %d for ReissueV1 transaction", tx.Type)
	}
	tx.Version = 1
	var r reissue
	err := r.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV1 transaction body")
	}
	tx.reissue = r
	return nil
}

//Sign use given private key to calculate signature of the transaction.
//This function also calculates digest of transaction data and assigns it to ID field.
func (tx *ReissueV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign ReissueV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign ReissueV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the signature of the transaction is valid for given public key.
func (tx *ReissueV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of ReissueV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *ReissueV1) MarshalBinary() ([]byte, error) {
	sl := crypto.SignatureSize
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ReissueV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, 1+sl+bl)
	buf[0] = byte(tx.Type)
	copy(buf[1:], tx.Signature[:])
	copy(buf[1+sl:], b)
	return buf, nil
}

//UnmarshalBinary reads transaction from its binary representation.
func (tx *ReissueV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < reissueV1MinLen {
		return errors.Errorf("not enough data for ReissueV1 transaction, expected not less then %d, received %d", reissueV1MinLen, l)
	}
	if data[0] != byte(ReissueTransaction) {
		return errors.Errorf("incorrect transaction type %d for ReissueV1 transaction", data[0])
	}
	data = data[1:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	data = data[crypto.SignatureSize:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV1 transaction")
	}
	d, err := crypto.FastHash(data)
	if err != nil {
		return errors.Wrap(err, "failed to hash ReissueV1 transaction")
	}
	tx.ID = &d
	return nil
}

//ReissueV2 same as ReissueV1 but version 2 with Proofs.
type ReissueV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ChainID byte            `json:"-"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	reissue
}

func (ReissueV2) Transaction() {}

//NewUnsignedReissueV2 creates new ReissueV2 transaction without signature and ID.
func NewUnsignedReissueV2(chainID byte, senderPK crypto.PublicKey, assetID crypto.Digest, quantity uint64, reissuable bool, timestamp, fee uint64) (*ReissueV2, error) {
	r, err := newReissue(senderPK, assetID, quantity, reissuable, timestamp, fee)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ReissueV2 transaction")
	}
	return &ReissueV2{Type: ReissueTransaction, Version: 2, ChainID: chainID, reissue: *r}, nil
}

func (tx *ReissueV2) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, reissueV2BodyLen)
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	buf[2] = tx.ChainID
	b, err := tx.reissue.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ReissueV2 body")
	}
	copy(buf[3:], b)
	return buf, nil
}

func (tx *ReissueV2) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < reissueV2BodyLen {
		return errors.Errorf("%d bytes is not enough for ReissueV2 transaction, expected not less then %d bytes", l, reissueV2BodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != ReissueTransaction {
		return errors.Errorf("unexpected transaction type %d for ReissueV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	if v := tx.Version; v != 2 {
		return errors.Errorf("unexpected version %d for ReissueV2 transaction, expected 2", v)
	}
	tx.ChainID = data[2]
	var r reissue
	err := r.unmarshalBinary(data[3:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV2 body from bytes")
	}
	tx.reissue = r
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *ReissueV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign ReissueV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign ReissueV2 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign ReissueV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *ReissueV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of ReissueV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary writes ReissueV2 transaction to its bytes representation.
func (tx *ReissueV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ReissueV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal ReissueV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ReissueV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads ReissueV2 from its bytes representation.
func (tx *ReissueV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < reissueV2MinLen {
		return errors.Errorf("not enough data for ReissueV2 transaction, expected not less then %d, received %d", reissueV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV2 transaction from bytes")
	}
	bb := data[:reissueV2BodyLen]
	data = data[reissueV2BodyLen:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ReissueV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type burn struct {
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	AssetID   crypto.Digest    `json:"assetId"`
	Amount    uint64           `json:"amount"`
	Timestamp uint64           `json:"timestamp,omitempty"`
	Fee       uint64           `json:"fee"`
}

func newBurn(senderPK crypto.PublicKey, assetID crypto.Digest, amount, timestamp, fee uint64) (*burn, error) {
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &burn{SenderPK: senderPK, AssetID: assetID, Amount: amount, Timestamp: timestamp, Fee: fee}, nil
}

func (b *burn) marshalBinary() ([]byte, error) {
	buf := make([]byte, burnLen)
	p := 0
	copy(buf[p:], b.SenderPK[:])
	p += crypto.PublicKeySize
	copy(buf[p:], b.AssetID[:])
	p += crypto.DigestSize
	binary.BigEndian.PutUint64(buf[p:], b.Amount)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], b.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], b.Timestamp)
	return buf, nil
}

func (b *burn) unmarshalBinary(data []byte) error {
	if l := len(data); l < burnLen {
		return errors.Errorf("%d bytes is not enough for burn, expected not less then %d", l, burnLen)
	}
	copy(b.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	copy(b.AssetID[:], data[:crypto.DigestSize])
	data = data[crypto.DigestSize:]
	b.Amount = binary.BigEndian.Uint64(data)
	data = data[8:]
	b.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	b.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//BurnV1 transaction allows to decrease the total supply of the existing asset. Asset must be reissuable.
type BurnV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	burn
}

func (BurnV1) Transaction() {}
func (tx BurnV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedBurnV1 creates new BurnV1 transaction with no signature and ID.
func NewUnsignedBurnV1(senderPK crypto.PublicKey, assetID crypto.Digest, amount, timestamp, fee uint64) (*BurnV1, error) {
	b, err := newBurn(senderPK, assetID, amount, timestamp, fee)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create BurnV1 transaction")
	}
	return &BurnV1{Type: BurnTransaction, Version: 1, burn: *b}, nil
}

func (tx *BurnV1) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, burnV1BodyLen)
	buf[0] = byte(tx.Type)
	b, err := tx.burn.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal BurnV1 transaction to bytes")
	}
	copy(buf[1:], b)
	return buf, nil
}

func (tx *BurnV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < burnV1BodyLen {
		return errors.Errorf("%d bytes is not enough for BurnV1 transaction, expected not less then %d", l, burnV1BodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != BurnTransaction {
		return errors.Errorf("unexpected transaction type %d for BurnV1 transaction", tx.Type)
	}
	tx.Version = 1
	var b burn
	err := b.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV1 transaction body")
	}
	tx.burn = b
	return nil
}

//Sign calculates and sets signature and ID of the transaction.
func (tx *BurnV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign BurnV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign BurnV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the signature of the transaction is valid for the given public key.
func (tx *BurnV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of BurnV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves transaction to
func (tx *BurnV1) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal BurnV1 transaction to bytes")
	}
	buf := make([]byte, burnV1Len)
	copy(buf, b)
	copy(buf[burnV1BodyLen:], tx.Signature[:])
	return buf, nil
}

//UnmarshalBinary reads transaction form its binary representation.
func (tx *BurnV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < burnV1Len {
		return errors.Errorf("not enough data for BurnV1 transaction, expected not less then %d, received %d", burnV1Len, l)
	}
	err := tx.bodyUnmarshalBinary(data[:burnV1BodyLen])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV1 transaction")
	}
	var s crypto.Signature
	copy(s[:], data[burnV1BodyLen:burnV1BodyLen+crypto.SignatureSize])
	tx.Signature = &s
	d, err := crypto.FastHash(data[:burnV1BodyLen])
	if err != nil {
		return errors.Wrap(err, "failed to hash BurnV1 transaction")
	}
	tx.ID = &d
	return nil
}

//BurnV2 same as BurnV1 but version 2 with Proofs.
type BurnV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ChainID byte            `json:"-"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	burn
}

func (BurnV2) Transaction() {}

//NewUnsignedBurnV2 creates new BurnV2 transaction without proofs and ID.
func NewUnsignedBurnV2(chainID byte, senderPK crypto.PublicKey, assetID crypto.Digest, amount, timestamp, fee uint64) (*BurnV2, error) {
	b, err := newBurn(senderPK, assetID, amount, timestamp, fee)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create BurnV2 transaction")
	}
	return &BurnV2{Type: BurnTransaction, Version: 2, ChainID: chainID, burn: *b}, nil
}

func (tx *BurnV2) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, burnV2BodyLen)
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	buf[2] = tx.ChainID
	b, err := tx.burn.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal BurnV2 body")
	}
	copy(buf[3:], b)
	return buf, nil
}

func (tx *BurnV2) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < burnV2BodyLen {
		return errors.Errorf("%d bytes is not enough for BurnV2 transaction, expected not less then %d bytes", l, burnV2BodyLen)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != BurnTransaction {
		return errors.Errorf("unexpected transaction type %d for BurnV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	if v := tx.Version; v != 2 {
		return errors.Errorf("unexpected version %d for BurnV2 transaction, expected 2", v)
	}
	tx.ChainID = data[2]
	var b burn
	err := b.unmarshalBinary(data[3:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV2 body from bytes")
	}
	tx.burn = b
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *BurnV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign BurnV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign BurnV2 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign BurnV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *BurnV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of BurnV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary writes BurnV2 transaction to its bytes representation.
func (tx *BurnV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal BurnV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal BurnV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal BurnV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads BurnV2 from its bytes representation.
func (tx *BurnV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < burnV2Len {
		return errors.Errorf("not enough data for BurnV2 transaction, expected not less then %d, received %d", burnV2BodyLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV2 transaction from bytes")
	}
	bb := data[:burnV2BodyLen]
	data = data[burnV2BodyLen:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal BurnV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

//ExchangeV1 is a transaction to store settlement on blockchain.
type ExchangeV1 struct {
	Type           TransactionType   `json:"type"`
	Version        byte              `json:"version,omitempty"`
	ID             *crypto.Digest    `json:"id,omitempty"`
	Signature      *crypto.Signature `json:"signature,omitempty"`
	SenderPK       crypto.PublicKey  `json:"senderPublicKey"`
	BuyOrder       OrderV1           `json:"order1"`
	SellOrder      OrderV1           `json:"order2"`
	Price          uint64            `json:"price"`
	Amount         uint64            `json:"amount"`
	BuyMatcherFee  uint64            `json:"buyMatcherFee"`
	SellMatcherFee uint64            `json:"sellMatcherFee"`
	Fee            uint64            `json:"fee"`
	Timestamp      uint64            `json:"timestamp,omitempty"`
}

func (ExchangeV1) Transaction() {}
func (tx ExchangeV1) GetID() []byte {
	return tx.ID.Bytes()
}

func NewUnsignedExchangeV1(buy, sell OrderV1, price, amount, buyMatcherFee, sellMatcherFee, fee, timestamp uint64) (*ExchangeV1, error) {
	if buy.Signature == nil {
		return nil, errors.New("buy order should be signed")
	}
	if sell.Signature == nil {
		return nil, errors.New("sell order should be signed")
	}
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if price <= 0 {
		return nil, errors.New("price should be positive")
	}
	if buyMatcherFee <= 0 {
		return nil, errors.New("buy matcher's fee should be positive")
	}
	if sellMatcherFee <= 0 {
		return nil, errors.New("sell matcher's fee should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &ExchangeV1{Type: ExchangeTransaction, Version: 1, SenderPK: buy.MatcherPK, BuyOrder: buy, SellOrder: sell, Price: price, Amount: amount, BuyMatcherFee: buyMatcherFee, SellMatcherFee: sellMatcherFee, Fee: fee, Timestamp: timestamp}, nil
}

func (tx *ExchangeV1) bodyMarshalBinary() ([]byte, error) {
	bob, err := tx.BuyOrder.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal ExchangeV1 body to bytes")
	}
	bol := uint32(len(bob))
	sob, err := tx.SellOrder.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal ExchangeV1 body to bytes")
	}
	sol := uint32(len(sob))
	var p uint32
	buf := make([]byte, exchangeV1FixedBodyLen+bol+sol)
	buf[0] = byte(tx.Type)
	p++
	binary.BigEndian.PutUint32(buf[p:], bol)
	p += 4
	binary.BigEndian.PutUint32(buf[p:], sol)
	p += 4
	copy(buf[p:], bob)
	p += bol
	copy(buf[p:], sob)
	p += sol
	binary.BigEndian.PutUint64(buf[p:], tx.Price)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Amount)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.BuyMatcherFee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.SellMatcherFee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	return buf, nil
}

func (tx *ExchangeV1) bodyUnmarshalBinary(data []byte) (int, error) {
	const expectedLen = exchangeV1FixedBodyLen + orderV1MinLen + orderV1MinLen
	if l := len(data); l < expectedLen {
		return 0, errors.Errorf("not enough data for ExchangeV1 transaction, expected not less then %d, received %d", expectedLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != ExchangeTransaction {
		return 0, errors.Errorf("unexpected transaction type %d for ExchangeV1 transaction", tx.Type)
	}
	tx.Version = 1
	n := 1
	bol := binary.BigEndian.Uint32(data[n:])
	n += 4
	sol := binary.BigEndian.Uint32(data[n:])
	n += 4
	var bo OrderV1
	err := bo.UnmarshalBinary(data[n:])
	if err != nil {
		return 0, errors.Wrapf(err, "failed to unmarshal ExchangeV1 body from bytes")
	}
	tx.BuyOrder = bo
	n += int(bol)
	var so OrderV1
	err = so.UnmarshalBinary(data[n:])
	if err != nil {
		return 0, errors.Wrapf(err, "failed to unmarshal ExchangeV1 body from bytes")
	}
	tx.SellOrder = so
	n += int(sol)
	tx.Price = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Amount = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.BuyMatcherFee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.SellMatcherFee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Fee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Timestamp = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.SenderPK = tx.BuyOrder.MatcherPK
	return n, nil
}

//Sing calculates ID and Signature of the transaction.
func (tx *ExchangeV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign ExchangeV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign ExchangeV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that signature of the transaction is valid.
func (tx *ExchangeV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of ExchangeV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *ExchangeV1) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ExchangeV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, bl+crypto.SignatureSize)
	copy(buf[0:], b)
	copy(buf[bl:], tx.Signature[:])
	return buf, nil
}

//UnmarshalBinary loads the transaction from its binary representation.
func (tx *ExchangeV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < exchangeV1MinLen {
		return errors.Errorf("not enough data for ExchangeV1 transaction, expected not less then %d, received %d", exchangeV1MinLen, l)
	}
	if data[0] != byte(ExchangeTransaction) {
		return errors.Errorf("incorrect transaction type %d for ExchangeV1 transaction", data[0])
	}
	bl, err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ExchangeV1 transaction from bytes")
	}
	bb := data[:bl]
	data = data[bl:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	d, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ExchangeV1 transaction from bytes")
	}
	tx.ID = &d
	return nil
}

//ExchangeV2 is a transaction to store settlement on blockchain.
type ExchangeV2 struct {
	Type           TransactionType  `json:"type"`
	Version        byte             `json:"version,omitempty"`
	ID             *crypto.Digest   `json:"id,omitempty"`
	Proofs         *ProofsV1        `json:"proofs,omitempty"`
	SenderPK       crypto.PublicKey `json:"senderPublicKey"`
	BuyOrder       Order            `json:"order1"`
	SellOrder      Order            `json:"order2"`
	Price          uint64           `json:"price"`
	Amount         uint64           `json:"amount"`
	BuyMatcherFee  uint64           `json:"buyMatcherFee"`
	SellMatcherFee uint64           `json:"sellMatcherFee"`
	Fee            uint64           `json:"fee"`
	Timestamp      uint64           `json:"timestamp,omitempty"`
}

func (ExchangeV2) Transaction() {}

func NewUnsignedExchangeV2(buy, sell Order, price, amount, buyMatcherFee, sellMatcherFee, fee, timestamp uint64) (*ExchangeV2, error) {
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if price <= 0 {
		return nil, errors.New("price should be positive")
	}
	if buyMatcherFee <= 0 {
		return nil, errors.New("buy matcher's fee should be positive")
	}
	if sellMatcherFee <= 0 {
		return nil, errors.New("sell matcher's fee should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &ExchangeV2{Type: ExchangeTransaction, Version: 2, SenderPK: buy.GetMatcherPK(), BuyOrder: buy, SellOrder: sell, Price: price, Amount: amount, BuyMatcherFee: buyMatcherFee, SellMatcherFee: sellMatcherFee, Fee: fee, Timestamp: timestamp}, nil
}

func (tx *ExchangeV2) marshalAsOrderV1(order Order) ([]byte, error) {
	o, ok := order.(OrderV1)
	if !ok {
		return nil, errors.New("failed to cast an order with version 1 to OrderV1")
	}
	b, err := o.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal OrderV1 to bytes")
	}
	l := len(b)
	buf := make([]byte, 4+1+l)
	binary.BigEndian.PutUint32(buf, uint32(l))
	buf[4] = 1
	copy(buf[5:], b)
	return buf, nil
}

func (tx *ExchangeV2) marshalAsOrderV2(order Order) ([]byte, error) {
	o, ok := order.(OrderV2)
	if !ok {
		return nil, errors.New("failed to cast an order with version 2 to OrderV2")
	}
	b, err := o.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal OrderV2 to bytes")
	}
	l := len(b)
	buf := make([]byte, 4+l)
	binary.BigEndian.PutUint32(buf, uint32(l))
	copy(buf[4:], b)
	return buf, nil
}

func (tx *ExchangeV2) bodyMarshalBinary() ([]byte, error) {
	var bob []byte
	var sob []byte
	var err error
	switch tx.BuyOrder.GetVersion() {
	case 1:
		bob, err = tx.marshalAsOrderV1(tx.BuyOrder)
	case 2:
		bob, err = tx.marshalAsOrderV2(tx.BuyOrder)
	default:
		err = errors.Errorf("invalid BuyOrder version %d", tx.BuyOrder.GetVersion())
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal buy order to bytes")
	}
	bol := uint32(len(bob))
	switch tx.SellOrder.GetVersion() {
	case 1:
		sob, err = tx.marshalAsOrderV1(tx.SellOrder)
	case 2:
		sob, err = tx.marshalAsOrderV2(tx.SellOrder)
	default:
		err = errors.Errorf("invalid SellOrder version %d", tx.SellOrder.GetVersion())
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal sell order to bytes")
	}
	sol := uint32(len(sob))
	var p uint32
	buf := make([]byte, exchangeV2FixedBodyLen+(bol-4)+(sol-4))
	buf[0] = 0
	buf[1] = byte(tx.Type)
	buf[2] = tx.Version
	p += 3
	copy(buf[p:], bob)
	p += bol
	copy(buf[p:], sob)
	p += sol
	binary.BigEndian.PutUint64(buf[p:], tx.Price)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Amount)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.BuyMatcherFee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.SellMatcherFee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	return buf, nil
}

func (tx *ExchangeV2) unmarshalOrder(data []byte) (int, *Order, error) {
	var r Order
	n := 0
	ol := binary.BigEndian.Uint32(data)
	n += 4
	switch data[n] {
	case 1:
		n++
		var o OrderV1
		err := o.UnmarshalBinary(data[n:])
		if err != nil {
			return 0, nil, errors.Wrap(err, "failed to unmarshal OrderV1")
		}
		n += int(ol)
		r = o
	case 2:
		var o OrderV2
		err := o.UnmarshalBinary(data[n:])
		if err != nil {
			return 0, nil, errors.Wrap(err, "failed to unmarshal OrderV2")
		}
		n += int(ol)
		r = o
	default:
		return 0, nil, errors.Errorf("unexpected order version %d", data[n])
	}
	return n, &r, nil
}

func (tx *ExchangeV2) bodyUnmarshalBinary(data []byte) (int, error) {
	n := 0
	if l := len(data); l < exchangeV2FixedBodyLen {
		return 0, errors.Errorf("not enough data for ExchangeV2 body, expected not less then %d, received %d", exchangeV2FixedBodyLen, l)
	}
	if v := data[n]; v != 0 {
		return 0, errors.Errorf("unexpected first byte %d of ExchangeV2 body, expected 0", v)
	}
	n++
	tx.Type = TransactionType(data[n])
	if tx.Type != ExchangeTransaction {
		return 0, errors.Errorf("unexpected transaction type %d for ExchangeV2 transaction", tx.Type)
	}
	n++
	tx.Version = data[n]
	if tx.Version != 2 {
		return 0, errors.Errorf("unexpected transaction version %d for ExchangeV2 transaction", tx.Version)
	}
	n++
	l, o, err := tx.unmarshalOrder(data[n:])
	if err != nil {
		return 0, errors.Wrap(err, "failed to unmarshal buy order")
	}
	tx.BuyOrder = *o
	n += l
	l, o, err = tx.unmarshalOrder(data[n:])
	if err != nil {
		return 0, errors.Wrap(err, "failed to unmarshal sell order")
	}
	tx.SellOrder = *o
	n += l
	tx.Price = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Amount = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.BuyMatcherFee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.SellMatcherFee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Fee = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.Timestamp = binary.BigEndian.Uint64(data[n:])
	n += 8
	tx.SenderPK = tx.BuyOrder.GetMatcherPK()
	return n, nil
}

//Sign calculates transaction signature using given secret key.
func (tx *ExchangeV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign ExchangeV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign ExchangeV2 transaction")
	}
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign ExchangeV2 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the transaction signature is valid for given public key.
func (tx *ExchangeV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of ExchangeV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *ExchangeV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ExchangeV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal ExchangeV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal ExchangeV2 transaction to bytes")
	}
	buf := make([]byte, bl+len(pb))
	copy(buf, bb)
	copy(buf[bl:], pb)
	return buf, nil
}

//UnmarshalBinary loads the transaction from its binary representation.
func (tx *ExchangeV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < exchangeV2MinLen {
		return errors.Errorf("not enough data for ExchangeV2 transaction, expected not less then %d, received %d", exchangeV2MinLen, l)
	}
	bl, err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ExchangeV2 transaction from bytes")
	}
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ExchangeV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal ExchangeV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type lease struct {
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	Recipient Recipient        `json:"recipient"`
	Amount    uint64           `json:"amount"`
	Fee       uint64           `json:"fee"`
	Timestamp uint64           `json:"timestamp,omitempty"`
}

func newLease(senderPK crypto.PublicKey, recipient Address, amount, fee, timestamp uint64) (*lease, error) {
	if ok, err := recipient.Validate(); !ok {
		return nil, errors.Wrap(err, "failed to create new unsigned LeaseV1 transaction")
	}
	if amount <= 0 {
		return nil, errors.New("amount should be positive")
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &lease{SenderPK: senderPK, Recipient: NewRecipientFromAddress(recipient), Amount: amount, Fee: fee, Timestamp: timestamp}, nil
}

func (l *lease) marshalBinary() ([]byte, error) {
	rl := l.Recipient.len
	buf := make([]byte, leaseLen+rl)
	p := 0
	copy(buf[p:], l.SenderPK[:])
	p += crypto.PublicKeySize
	rb, err := l.Recipient.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal lease to bytes")
	}
	copy(buf[p:], rb)
	p += rl
	binary.BigEndian.PutUint64(buf[p:], l.Amount)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], l.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], l.Timestamp)
	return buf, nil
}

func (l *lease) unmarshalBinary(data []byte) error {
	if l := len(data); l < leaseLen {
		return errors.Errorf("not enough data for lease, expected not less then %d, received %d", leaseLen, l)
	}
	copy(l.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	err := l.Recipient.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal lease from bytes")
	}
	data = data[l.Recipient.len:]
	l.Amount = binary.BigEndian.Uint64(data)
	data = data[8:]
	l.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	l.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//LeaseV1 is a transaction that allows to lease Waves to other account.
type LeaseV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	lease
}

func (LeaseV1) Transaction() {}
func (tx LeaseV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedLeaseV1 creates new LeaseV1 transaction without signature and ID set.
func NewUnsignedLeaseV1(senderPK crypto.PublicKey, recipient Address, amount, fee, timestamp uint64) (*LeaseV1, error) {
	l, err := newLease(senderPK, recipient, amount, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create LeaseV1 transaction")
	}
	return &LeaseV1{Type: LeaseTransaction, Version: 1, lease: *l}, nil
}

func (tx *LeaseV1) bodyMarshalBinary() ([]byte, error) {
	rl := tx.Recipient.len
	buf := make([]byte, leaseV1BodyLen+rl)
	buf[0] = byte(tx.Type)
	b, err := tx.lease.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseV1 transaction to bytes")
	}
	copy(buf[1:], b)
	return buf, nil
}

func (tx *LeaseV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseV1BodyLen {
		return errors.Errorf("not enough data for LeaseV1 transaction, expected not less then %d, received %d", leaseV1BodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != LeaseTransaction {
		return errors.Errorf("unexpected transaction type %d for LeaseV1 transaction", tx.Type)
	}
	tx.Version = 1
	var l lease
	err := l.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV1 transaction from bytes")
	}
	tx.lease = l
	return nil
}

//Sign calculates ID and Signature of the transaction.
func (tx *LeaseV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that the signature of the transaction is valid for the given public key.
func (tx *LeaseV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of LeaseV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *LeaseV1) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, bl+crypto.SignatureSize)
	copy(buf[0:], b)
	copy(buf[bl:], tx.Signature[:])
	return buf, nil
}

//UnmarshalBinary reads the transaction from bytes slice.
func (tx *LeaseV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseV1MinLen {
		return errors.Errorf("not enough data for LeaseV1 transaction, expected not less then %d, received %d", leaseV1MinLen, l)
	}
	if data[0] != byte(LeaseTransaction) {
		return errors.Errorf("incorrect transaction type %d for LeaseV1 transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV1 transaction from bytes")
	}
	bl := leaseV1BodyLen + tx.Recipient.len
	b := data[:bl]
	data = data[bl:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV1 transaction from bytes")
	}
	tx.ID = &d
	return nil
}

//LeaseV2 is a second version of the LeaseV1 transaction.
type LeaseV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	lease
}

func (LeaseV2) Transaction() {}

//NewUnsignedLeaseV2 creates new LeaseV1 transaction without signature and ID set.
func NewUnsignedLeaseV2(senderPK crypto.PublicKey, recipient Address, amount, fee, timestamp uint64) (*LeaseV2, error) {
	l, err := newLease(senderPK, recipient, amount, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create LeaseV2 transaction")
	}
	return &LeaseV2{Type: LeaseTransaction, Version: 2, lease: *l}, nil
}

func (tx *LeaseV2) bodyMarshalBinary() ([]byte, error) {
	rl := tx.Recipient.len
	buf := make([]byte, leaseV2BodyLen+rl)
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	buf[2] = 0 //Always zero, reserved for future extension of leasing assets.
	b, err := tx.lease.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseV1 transaction to bytes")
	}
	copy(buf[3:], b)
	return buf, nil
}

func (tx *LeaseV2) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseV2BodyLen {
		return errors.Errorf("not enough data for LeaseV2 transaction, expected not less then %d, received %d", leaseV2BodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != LeaseTransaction {
		return errors.Errorf("unexpected transaction type %d for LeaseV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	if tx.Version != 2 {
		return errors.Errorf("unexpected version %d for LeaseV2 transaction, expected 2", tx.Version)
	}
	var l lease
	err := l.unmarshalBinary(data[3:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV2 transaction from bytes")
	}
	tx.lease = l
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *LeaseV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseV2 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *LeaseV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of LeaseV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *LeaseV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal LeaseV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads the transaction from bytes slice.
func (tx *LeaseV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseV2MinLen {
		return errors.Errorf("not enough data for LeaseV2 transaction, expected not less then %d, received %d", leaseV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV2 transaction from bytes")
	}
	bl := leaseV2BodyLen + tx.Recipient.len
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type leaseCancel struct {
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	LeaseID   crypto.Digest    `json:"leaseId"`
	Fee       uint64           `json:"fee"`
	Timestamp uint64           `json:"timestamp,omitempty"`
}

//NewUnsignedLeaseCancelV1 creates new LeaseCancelV1 transaction structure without a signature and an ID.
func newLeaseCancel(senderPK crypto.PublicKey, leaseID crypto.Digest, fee, timestamp uint64) (*leaseCancel, error) {
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &leaseCancel{SenderPK: senderPK, LeaseID: leaseID, Fee: fee, Timestamp: timestamp}, nil
}

func (lc *leaseCancel) marshalBinary() ([]byte, error) {
	buf := make([]byte, leaseCancelLen)
	p := 0
	copy(buf[p:], lc.SenderPK[:])
	p += crypto.PublicKeySize
	binary.BigEndian.PutUint64(buf[p:], lc.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], lc.Timestamp)
	p += 8
	copy(buf[p:], lc.LeaseID[:])
	return buf, nil
}

func (lc *leaseCancel) unmarshalBinary(data []byte) error {
	if l := len(data); l < leaseCancelLen {
		return errors.Errorf("not enough data for leaseCancel, expected not less then %d, received %d", leaseCancelLen, l)
	}
	copy(lc.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	lc.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	lc.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	copy(lc.LeaseID[:], data[:crypto.DigestSize])
	return nil
}

//LeaseCancelV1 transaction can be used to cancel previously created leasing.
type LeaseCancelV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	leaseCancel
}

func (LeaseCancelV1) Transaction() {}
func (tx LeaseCancelV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedLeaseCancelV1 creates new LeaseCancelV1 transaction structure without a signature and an ID.
func NewUnsignedLeaseCancelV1(senderPK crypto.PublicKey, leaseID crypto.Digest, fee, timestamp uint64) (*LeaseCancelV1, error) {
	lc, err := newLeaseCancel(senderPK, leaseID, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create LeaseCancelV1 transaction")
	}
	return &LeaseCancelV1{Type: LeaseCancelTransaction, Version: 1, leaseCancel: *lc}, nil
}

func (tx *LeaseCancelV1) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, leaseCancelV1BodyLen)
	buf[0] = byte(tx.Type)
	b, err := tx.leaseCancel.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseCancelV1 to bytes")
	}
	copy(buf[1:], b)
	return buf, nil
}

func (tx *LeaseCancelV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseCancelV1BodyLen {
		return errors.Errorf("not enough data for LeaseCancelV1 transaction, expected not less then %d, received %d", leaseCancelV1BodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != LeaseCancelTransaction {
		return errors.Errorf("unexpected transaction type %d for LeaseCancelV1 transaction", tx.Type)

	}
	tx.Version = 1
	var lc leaseCancel
	err := lc.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV1 from bytes")
	}
	tx.leaseCancel = lc
	return nil
}

func (tx *LeaseCancelV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseCancelV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseCancelV1 transaction")
	}
	tx.ID = &d
	return nil
}

//Verify checks that signature of the transaction is valid for the given public key.
func (tx *LeaseCancelV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of LeaseCancelV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

//MarshalBinary saves transaction to its binary representation.
func (tx *LeaseCancelV1) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseCancelV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, bl+crypto.SignatureSize)
	copy(buf[0:], b)
	copy(buf[bl:], tx.Signature[:])
	return buf, nil
}

func (tx *LeaseCancelV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseCancelV1MinLen {
		return errors.Errorf("not enough data for LeaseCancelV1 transaction, expected not less then %d, received %d", leaseCancelV1MinLen, l)
	}
	if data[0] != byte(LeaseCancelTransaction) {
		return errors.Errorf("incorrect transaction type %d for LeaseCancelV1 transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV1 transaction from bytes")
	}
	b := data[:leaseCancelV1BodyLen]
	data = data[leaseCancelV1BodyLen:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	d, err := crypto.FastHash(b)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV1 transaction from bytes")
	}
	tx.ID = &d
	return nil
}

//LeaseCancelV2 same as LeaseCancelV1 but with proofs.
type LeaseCancelV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ChainID byte            `json:"-"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	leaseCancel
}

func (LeaseCancelV2) Transaction() {}

//NewUnsignedLeaseCancelV2 creates new LeaseCancelV2 transaction structure without a signature and an ID.
func NewUnsignedLeaseCancelV2(chainID byte, senderPK crypto.PublicKey, leaseID crypto.Digest, fee, timestamp uint64) (*LeaseCancelV2, error) {
	lc, err := newLeaseCancel(senderPK, leaseID, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create LeaseCancelV2 transaction")
	}
	return &LeaseCancelV2{Type: LeaseCancelTransaction, Version: 2, ChainID: chainID, leaseCancel: *lc}, nil
}

func (tx *LeaseCancelV2) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, leaseCancelV2BodyLen)
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	buf[2] = tx.ChainID
	b, err := tx.leaseCancel.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseCancelV2 to bytes")
	}
	copy(buf[3:], b)
	return buf, nil
}

func (tx *LeaseCancelV2) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseCancelV2BodyLen {
		return errors.Errorf("not enough data for LeaseCancelV2 transaction, expected not less then %d, received %d", leaseCancelV2BodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != LeaseCancelTransaction {
		return errors.Errorf("unexpected transaction type %d for LeaseCancelV2 transaction", tx.Type)

	}
	tx.Version = data[1]
	if tx.Version != 2 {
		return errors.Errorf("unexpected version %d for LeaseCancelV2, expected 2", tx.Version)
	}
	tx.ChainID = data[2]
	var lc leaseCancel
	err := lc.unmarshalBinary(data[3:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV2 from bytes")
	}
	tx.leaseCancel = lc
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *LeaseCancelV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseCancelV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseCancelV2 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign LeaseCancelV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *LeaseCancelV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of LeaseCancelV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *LeaseCancelV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseCancelV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal LeaseCancelV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LeaseCancelV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads the transaction from bytes slice.
func (tx *LeaseCancelV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < leaseCancelV2MinLen {
		return errors.Errorf("not enough data for LeaseCancelV2 transaction, expected not less then %d, received %d", leaseCancelV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV2 transaction from bytes")
	}
	bb := data[:leaseCancelV2BodyLen]
	data = data[leaseCancelV2BodyLen:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV2 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal LeaseCancelV2 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

type createAlias struct {
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	Alias     Alias            `json:"alias"`
	Fee       uint64           `json:"fee"`
	Timestamp uint64           `json:"timestamp,omitempty"`
}

func newCreateAlias(senderPK crypto.PublicKey, alias Alias, fee, timestamp uint64) (*createAlias, error) {
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &createAlias{SenderPK: senderPK, Alias: alias, Fee: fee, Timestamp: timestamp}, nil
}

func (ca *createAlias) marshalBinary() ([]byte, error) {
	p := 0
	buf := make([]byte, createAliasLen+len(ca.Alias.Alias))
	copy(buf[p:], ca.SenderPK[:])
	p += crypto.PublicKeySize
	ab, err := ca.Alias.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal createAlias to bytes")
	}
	al := len(ab)
	binary.BigEndian.PutUint16(buf[p:], uint16(al))
	p += 2
	copy(buf[p:], ab)
	p += al
	binary.BigEndian.PutUint64(buf[p:], ca.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], ca.Timestamp)
	return buf, nil
}

func (ca *createAlias) unmarshalBinary(data []byte) error {
	if l := len(data); l < createAliasLen {
		return errors.Errorf("not enough data for createAlias, expected not less then %d, received %d", createAliasLen, l)
	}
	copy(ca.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	al := binary.BigEndian.Uint16(data)
	data = data[2:]
	err := ca.Alias.UnmarshalBinary(data[:al])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal createAlias from bytes")
	}
	data = data[al:]
	ca.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	ca.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

func (ca *createAlias) id() (*crypto.Digest, error) {
	ab, err := ca.Alias.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get CreateAlias transaction ID")
	}
	al := len(ab)
	buf := make([]byte, 1+al)
	buf[0] = byte(CreateAliasTransaction)
	copy(buf[1:], ab)
	d, err := crypto.FastHash(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get CreateAlias transaction ID")
	}
	return &d, err
}

type CreateAliasV1 struct {
	Type      TransactionType   `json:"type"`
	Version   byte              `json:"version,omitempty"`
	ID        *crypto.Digest    `json:"id,omitempty"`
	Signature *crypto.Signature `json:"signature,omitempty"`
	createAlias
}

func (CreateAliasV1) Transaction() {}
func (tx CreateAliasV1) GetID() []byte {
	return tx.ID.Bytes()
}

func NewUnsignedCreateAliasV1(senderPK crypto.PublicKey, alias Alias, fee, timestamp uint64) (*CreateAliasV1, error) {
	ca, err := newCreateAlias(senderPK, alias, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CreateAliasV1 transaction")
	}
	return &CreateAliasV1{Type: CreateAliasTransaction, Version: 1, createAlias: *ca}, nil
}

func (tx *CreateAliasV1) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, createAliasV1FixedBodyLen+len(tx.Alias.Alias))
	buf[0] = byte(tx.Type)
	b, err := tx.createAlias.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CreateAliasV1 transaction body to bytes")
	}
	copy(buf[1:], b)
	return buf, nil
}

func (tx *CreateAliasV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < createAliasV1FixedBodyLen {
		return errors.Errorf("not enough data for CreateAliasV1 transaction, expected not less then %d, received %d", createAliasV1FixedBodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != CreateAliasTransaction {
		return errors.Errorf("unexpected transaction type %d for CreateAliasV1 transaction", tx.Type)
	}
	tx.Version = 1
	var ca createAlias
	err := ca.unmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV1 transaction from bytes")
	}
	tx.createAlias = ca
	return nil
}

func (tx *CreateAliasV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign CreateAliasV1 transaction")
	}
	s := crypto.Sign(secretKey, b)
	tx.Signature = &s
	tx.ID, err = tx.createAlias.id()
	if err != nil {
		return errors.Wrap(err, "failed to sign CreateAliasV1 transaction")
	}
	return nil
}

func (tx *CreateAliasV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, errors.New("empty signature")
	}
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of CreateAliasV1 transaction")
	}
	return crypto.Verify(publicKey, *tx.Signature, b), nil
}

func (tx *CreateAliasV1) MarshalBinary() ([]byte, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CreateAliasV1 transaction to bytes")
	}
	bl := len(b)
	buf := make([]byte, bl+crypto.SignatureSize)
	copy(buf[0:], b)
	copy(buf[bl:], tx.Signature[:])
	return buf, nil
}

func (tx *CreateAliasV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < createAliasV1MinLen {
		return errors.Errorf("not enough data for CreateAliasV1 transaction, expected not less then %d, received %d", createAliasV1MinLen, l)
	}
	if data[0] != byte(CreateAliasTransaction) {
		return errors.Errorf("incorrect transaction type %d for CreateAliasV1 transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV1 transaction from bytes")
	}
	bl := createAliasV1FixedBodyLen + len(tx.Alias.Alias)
	data = data[bl:]
	var s crypto.Signature
	copy(s[:], data[:crypto.SignatureSize])
	tx.Signature = &s
	tx.ID, err = tx.createAlias.id()
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV1 transaction from bytes")
	}
	return nil
}

type CreateAliasV2 struct {
	Type    TransactionType `json:"type"`
	Version byte            `json:"version,omitempty"`
	ID      *crypto.Digest  `json:"id,omitempty"`
	Proofs  *ProofsV1       `json:"proofs,omitempty"`
	createAlias
}

func (CreateAliasV2) Transaction() {}

func NewUnsignedCreateAliasV2(senderPK crypto.PublicKey, alias Alias, fee, timestamp uint64) (*CreateAliasV2, error) {
	ca, err := newCreateAlias(senderPK, alias, fee, timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CreateAliasV1 transaction")
	}
	return &CreateAliasV2{Type: CreateAliasTransaction, Version: 2, createAlias: *ca}, nil
}

func (tx *CreateAliasV2) bodyMarshalBinary() ([]byte, error) {
	buf := make([]byte, createAliasV2FixedBodyLen+len(tx.Alias.Alias))
	buf[0] = byte(tx.Type)
	buf[1] = tx.Version
	b, err := tx.createAlias.marshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CreateAliasV2 transaction body to bytes")
	}
	copy(buf[2:], b)
	return buf, nil
}

func (tx *CreateAliasV2) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < createAliasV2FixedBodyLen {
		return errors.Errorf("not enough data for CreateAliasV2 transaction, expected not less then %d, received %d", createAliasV2FixedBodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	if tx.Type != CreateAliasTransaction {
		return errors.Errorf("unexpected transaction type %d for CreateAliasV2 transaction", tx.Type)
	}
	tx.Version = data[1]
	if tx.Version != 2 {
		return errors.Errorf("unexpected version %d for CreateAliasV2 transaction", tx.Version)
	}
	var ca createAlias
	err := ca.unmarshalBinary(data[2:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV2 transaction from bytes")
	}
	tx.createAlias = ca
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *CreateAliasV2) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign CreateAliasV2 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign CreateAliasV2 transaction")
	}
	tx.ID, err = tx.createAlias.id()
	if err != nil {
		return errors.Wrap(err, "failed to sign CreateAliasV2 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *CreateAliasV2) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of CreateAliasV2 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *CreateAliasV2) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CreateAliasV2 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal CreateAliasV2 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CreateAliasV2 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads the transaction from bytes slice.
func (tx *CreateAliasV2) UnmarshalBinary(data []byte) error {
	if l := len(data); l < createAliasV2MinLen {
		return errors.Errorf("not enough data for CreateAliasV2 transaction, expected not less then %d, received %d", createAliasV2MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV2 transaction from bytes")
	}
	data = data[createAliasV2FixedBodyLen+len(tx.Alias.Alias):]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV2 transaction from bytes")
	}
	tx.Proofs = &p
	tx.ID, err = tx.createAlias.id()
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal CreateAliasV2 transaction from bytes")
	}
	return nil
}

type MassTransferEntry struct {
	Recipient Recipient `json:"recipient"`
	Amount    uint64    `json:"amount"`
}

func (e *MassTransferEntry) MarshalBinary() ([]byte, error) {
	rb, err := e.Recipient.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal MassTransferEntry")
	}
	rl := e.Recipient.len
	buf := make([]byte, massTransferEntryLen+rl)
	copy(buf, rb)
	binary.BigEndian.PutUint64(buf[rl:], e.Amount)
	return buf, nil
}

func (e *MassTransferEntry) UnmarshalBinary(data []byte) error {
	if l := len(data); l < massTransferEntryLen {
		return errors.Errorf("not enough data to unmarshal MassTransferEntry from byte, expected %d, received %d bytes", massTransferEntryLen, l)
	}
	err := e.Recipient.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferEntry from bytes")
	}
	e.Amount = binary.BigEndian.Uint64(data[e.Recipient.len:])
	return nil
}

//MassTransferV1 is a transaction that performs multiple transfers of one asset to the accounts at once.
type MassTransferV1 struct {
	Type       TransactionType     `json:"type"`
	Version    byte                `json:"version,omitempty"`
	ID         *crypto.Digest      `json:"id,omitempty"`
	Proofs     *ProofsV1           `json:"proofs,omitempty"`
	SenderPK   crypto.PublicKey    `json:"senderPublicKey"`
	Asset      OptionalAsset       `json:"assetId"`
	Transfers  []MassTransferEntry `json:"transfers"`
	Timestamp  uint64              `json:"timestamp,omitempty"`
	Fee        uint64              `json:"fee"`
	Attachment Attachment          `json:"attachment,omitempty"`
}

func (MassTransferV1) Transaction() {}
func (tx MassTransferV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedMassTransferV1 creates new MassTransferV1 transaction structure without signature and ID.
func NewUnsignedMassTransferV1(senderPK crypto.PublicKey, asset OptionalAsset, transfers []MassTransferEntry, fee, timestamp uint64, attachment string) (*MassTransferV1, error) {
	if len(transfers) == 0 {
		return nil, errors.New("empty transfers")
	}
	for _, t := range transfers {
		if t.Amount <= 0 {
			return nil, errors.New("at least one of the transfers has non-positive amount")
		}
	}
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	if len(attachment) > maxAttachmentLengthBytes {
		return nil, errors.New("attachment too long")
	}
	return &MassTransferV1{Type: MassTransferTransaction, Version: 1, SenderPK: senderPK, Asset: asset, Transfers: transfers, Fee: fee, Timestamp: timestamp, Attachment: Attachment(attachment)}, nil
}

func (tx *MassTransferV1) bodyAndAssetLen() (int, int) {
	n := len(tx.Transfers)
	l := 0
	if tx.Asset.Present {
		l += crypto.DigestSize
	}
	rls := 0
	for _, e := range tx.Transfers {
		rls += e.Recipient.len
	}
	al := len(tx.Attachment)
	return massTransferV1FixedLen + l + n*massTransferEntryLen + rls + al, l
}

func (tx *MassTransferV1) bodyMarshalBinary() ([]byte, error) {
	var p int
	n := len(tx.Transfers)
	bl, al := tx.bodyAndAssetLen()
	buf := make([]byte, bl)
	buf[p] = byte(tx.Type)
	p++
	buf[p] = tx.Version
	p++
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	ab, err := tx.Asset.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal MassTransferV1 transaction body to bytes")
	}
	copy(buf[p:], ab)
	p += 1 + al
	binary.BigEndian.PutUint16(buf[p:], uint16(n))
	p += 2
	for _, t := range tx.Transfers {
		tb, err := t.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal MassTransferV1 transaction body to bytes")
		}
		copy(buf[p:], tb)
		p += massTransferEntryLen + t.Recipient.len
	}
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	PutStringWithUInt16Len(buf[p:], tx.Attachment.String())
	return buf, nil
}

func (tx *MassTransferV1) bodyUnmarshalBinary(data []byte) error {
	tx.Type = TransactionType(data[0])
	tx.Version = data[1]
	if l := len(data); l < massTransferV1MinLen {
		return errors.Errorf("not enough data for MassTransferV1 transaction, expected not less then %d, received %d", massTransferV1MinLen, l)
	}
	if tx.Type != MassTransferTransaction {
		return errors.Errorf("unexpected transaction type %d for MassTransferV1 transaction", tx.Type)
	}
	if tx.Version != 1 {
		return errors.Errorf("unexpected version %d for MassTransferV1 transaction", tx.Version)
	}
	data = data[2:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	err := tx.Asset.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferV1 from bytes")
	}
	data = data[1:]
	if tx.Asset.Present {
		data = data[crypto.DigestSize:]
	}
	n := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	var entries []MassTransferEntry
	for i := 0; i < n; i++ {
		var e MassTransferEntry
		err := e.UnmarshalBinary(data)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal MassTransferV1 transaction body from bytes")
		}
		data = data[massTransferEntryLen+e.Recipient.len:]
		entries = append(entries, e)
	}
	tx.Transfers = entries
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	at, err := StringWithUInt16Len(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferV1 transaction body from bytes")
	}
	tx.Attachment = Attachment(at)
	return nil
}

//Sign calculates signature and ID of the transaction.
func (tx *MassTransferV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign MassTransferV1 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign MassTransferV1 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign MassTransferV1 transaction")
	}
	return nil
}

//Verify checks that the signature is valid for the given public key.
func (tx *MassTransferV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of MassTransferV1 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to its binary representation.
func (tx *MassTransferV1) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal MassTransferV1 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal MassTransferV1 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal MassTransferV1 transaction to bytes")
	}
	pl := len(pb)
	buf := make([]byte, bl+pl)
	copy(buf[0:], bb)
	copy(buf[bl:], pb)
	return buf, nil
}

//UnmarshalBinary loads transaction from its binary representation.
func (tx *MassTransferV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < massTransferV1MinLen {
		return errors.Errorf("not enough data for MassTransferV1 transaction, expected not less then %d, received %d", massTransferV1MinLen, l)
	}
	if data[0] != byte(MassTransferTransaction) {
		return errors.Errorf("incorrect transaction type %d for MassTransferV1 transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferV1 transaction from bytes")
	}
	bl, _ := tx.bodyAndAssetLen()
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferV1 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal MassTransferV1 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

//DataV1 is first version of the transaction that puts data to the key-value storage of an account.
type DataV1 struct {
	Type      TransactionType  `json:"type"`
	Version   byte             `json:"version,omitempty"`
	ID        *crypto.Digest   `json:"id,omitempty"`
	Proofs    *ProofsV1        `json:"proofs,omitempty"`
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	Entries   []DataEntry
	Fee       uint64 `json:"fee"`
	Timestamp uint64 `json:"timestamp,omitempty"`
}

func (DataV1) Transaction() {}
func (tx DataV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedData creates new Data transaction without proofs.
func NewUnsignedData(senderPK crypto.PublicKey, fee, timestamp uint64) (*DataV1, error) {
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &DataV1{Type: DataTransaction, Version: 1, SenderPK: senderPK, Fee: fee, Timestamp: timestamp}, nil
}

//AppendEntry adds the entry to the transaction.
func (tx *DataV1) AppendEntry(entry DataEntry) error {
	if len(entry.GetKey()) == 0 {
		return errors.Errorf("empty keys are not allowed")
	}
	key := entry.GetKey()
	for _, e := range tx.Entries {
		if e.GetKey() == key {
			return errors.Errorf("key '%s' already exist", key)
		}
	}
	tx.Entries = append(tx.Entries, entry)
	return nil
}

func (tx *DataV1) entriesLen() int {
	r := 0
	for _, e := range tx.Entries {
		r += e.binarySize()
	}
	return r
}

func (tx *DataV1) BodyMarshalBinary() ([]byte, error) {
	var p int
	n := len(tx.Entries)
	el := tx.entriesLen()
	buf := make([]byte, dataV1FixedBodyLen+el)
	buf[p] = byte(tx.Type)
	p++
	buf[p] = tx.Version
	p++
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	binary.BigEndian.PutUint16(buf[p:], uint16(n))
	p += 2
	for _, e := range tx.Entries {
		eb, err := e.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal DataV1 transaction body to bytes")
		}
		copy(buf[p:], eb)
		p += e.binarySize()
	}
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	return buf, nil
}

func (tx *DataV1) bodyUnmarshalBinary(data []byte) error {
	tx.Type = TransactionType(data[0])
	tx.Version = data[1]
	if l := len(data); l < dataV1FixedBodyLen {
		return errors.Errorf("not enough data for DataV1 transaction, expected not less then %d, received %d", dataV1FixedBodyLen, l)
	}
	if tx.Type != DataTransaction {
		return errors.Errorf("unexpected transaction type %d for DataV1 transaction", tx.Type)
	}
	if tx.Version != 1 {
		return errors.Errorf("unexpected version %d for DataV1 transaction", tx.Version)
	}
	data = data[2:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	n := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	for i := 0; i < n; i++ {
		var e DataEntry
		t, err := tx.extractValueType(data)
		if err != nil {
			return errors.Errorf("failed to extract type of data entry")
		}
		switch ValueType(t) {
		case Integer:
			var ie IntegerDataEntry
			err = ie.UnmarshalBinary(data)
			e = ie
		case Boolean:
			var be BooleanDataEntry
			err = be.UnmarshalBinary(data)
			e = be
		case Binary:
			var be BinaryDataEntry
			err = be.UnmarshalBinary(data)
			e = be
		case String:
			var se StringDataEntry
			err = se.UnmarshalBinary(data)
			e = se
		default:
			return errors.Errorf("unsupported ValueType %d", t)
		}
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal DataV1 transaction body from bytes")
		}
		data = data[e.binarySize():]
		err = tx.AppendEntry(e)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal DataV1 transaction body from bytes")
		}
	}
	tx.Timestamp = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	return nil
}

func (tx *DataV1) extractValueType(data []byte) (ValueType, error) {
	if l := len(data); l < 3 {
		return 0, errors.Errorf("not enough data to extract ValueType, expected not less than %d, received %d", 3, l)
	}
	kl := binary.BigEndian.Uint16(data)
	if l := len(data); l < int(kl)+2 {
		return 0, errors.Errorf("not enough data to extract ValueType, expected not less than %d, received %d", kl+2, l)
	}
	return ValueType(data[kl+2]), nil
}

//Sign use given secret key to calculate signature of the transaction.
func (tx *DataV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.BodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign DataV1 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign DataV1 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign DataV1 transaction")
	}
	return nil
}

//Verify chechs that the signature is valid for the given public key.
func (tx *DataV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.BodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of DataV1 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary saves the transaction to bytes.
func (tx *DataV1) MarshalBinary() ([]byte, error) {
	bb, err := tx.BodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal DataV1 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal DataV1 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal DataV1 transaction to bytes")
	}
	pl := len(pb)
	buf := make([]byte, 1+bl+pl)
	buf[0] = 0
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads the transaction from the bytes.
func (tx *DataV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < dataV1MinLen {
		return errors.Errorf("not enough data for DataV1 transaction, expected not less then %d, received %d", dataV1MinLen, l)
	}
	if data[0] != 0 {
		return errors.Errorf("unexpected first byte %d for DataV1 transaction", data[0])
	}
	err := tx.bodyUnmarshalBinary(data[1:])
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal DataV1 transaction from bytes")
	}
	bl := dataV1FixedBodyLen + tx.entriesLen()
	bb := data[1 : 1+bl]
	data = data[1+bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal DataV1 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal DataV1 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

//
//type DataEntryV1 struct {
//	K string `json:"key"`
//	T string `json:"type"`
//	value *interface{} `json:"value,omitempty"`
//}
//
//type DataEntryV1s struct {
//	Data []*DataEntryV1 `json:"data,omitempty"`
//}
//
//func (tx *DataV1) UnmarshalJSON(value []byte) error {
//	var tt  = new(DataEntryV1s)
//	err := json.Unmarshal(value, tt)
//	if err != nil {
//		return err
//	}
//
//	tx.Entries = make([]DataEntry, len(tt.Data))
//	for i, data := range tt.Data {
//		switch data.T {
//		case "integer":
//			tx.Entries[i] = new(IntegerDataEntry)
//		case "boolean":
//			tx.Entries[i] = new(BooleanDataEntry)
//		case "binary":
//			tx.Entries[i] = new(BinaryDataEntry)
//		case "string":
//			tx.Entries[i] = new(StringDataEntry)
//		default:
//			tx.Entries[i] = nil
//		}
//	}
//	return json.Unmarshal(value, tx)
//}

//SetScriptV1 is a transaction to set smart script on an account.
type SetScriptV1 struct {
	Type      TransactionType  `json:"type"`
	Version   byte             `json:"version,omitempty"`
	ID        *crypto.Digest   `json:"id,omitempty"`
	Proofs    *ProofsV1        `json:"proofs,omitempty"`
	ChainID   byte             `json:"-"`
	SenderPK  crypto.PublicKey `json:"senderPublicKey"`
	Script    []byte           `json:"script"`
	Fee       uint64           `json:"fee"`
	Timestamp uint64           `json:"timestamp,omitempty"`
}

func (SetScriptV1) Transaction() {}
func (tx SetScriptV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedSetScriptV1 creates new unsigned SetScriptV1 transaction.
func NewUnsignedSetScriptV1(chain byte, senderPK crypto.PublicKey, script []byte, fee, timestamp uint64) (*SetScriptV1, error) {
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &SetScriptV1{Type: SetScriptTransaction, Version: 1, ChainID: chain, SenderPK: senderPK, Script: script, Fee: fee, Timestamp: timestamp}, nil
}

//NonEmptyScript returns true if transaction contains non-empty script.
func (tx *SetScriptV1) NonEmptyScript() bool {
	return len(tx.Script) != 0
}

func (tx *SetScriptV1) bodyMarshalBinary() ([]byte, error) {
	var p int
	sl := 0
	if tx.NonEmptyScript() {
		sl = len(tx.Script) + 2
	}
	buf := make([]byte, setScriptV1FixedBodyLen+sl)
	buf[p] = byte(tx.Type)
	p++
	buf[p] = tx.Version
	p++
	buf[p] = tx.ChainID
	p++
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	PutBool(buf[p:], tx.NonEmptyScript())
	p++
	if tx.NonEmptyScript() {
		PutBytesWithUInt16Len(buf[p:], tx.Script)
		p += sl
	}
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	return buf, nil
}

func (tx *SetScriptV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < setScriptV1FixedBodyLen {
		return errors.Errorf("not enough data for SetScriptV1 transaction, expected not less then %d, received %d", setScriptV1FixedBodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	tx.Version = data[1]
	tx.ChainID = data[2]
	if tx.Type != SetScriptTransaction {
		return errors.Errorf("unexpected transaction type %d for SetScriptV1 transaction", tx.Type)
	}
	if tx.Version != 1 {
		return errors.Errorf("unexpected version %d for SetScriptV1 transaction", tx.Version)
	}
	data = data[3:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	p, err := Bool(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SetScripV1 transaction body from bytes")
	}
	data = data[1:]
	if p {
		s, err := BytesWithUInt16Len(data)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal SetScriptV1 transaction body from bytes")
		}
		tx.Script = s
		data = data[2+len(s):]
	}
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *SetScriptV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign SetScriptV1 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign SetScriptV1 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign SetScriptV1 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *SetScriptV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of SetScriptV1 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary writes SetScriptV1 transaction to its bytes representation.
func (tx *SetScriptV1) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SetScriptV1 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal SetScriptV1 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SetScriptV1 transaction to bytes")
	}
	buf := make([]byte, 1+bl+len(pb))
	copy(buf[1:], bb)
	copy(buf[1+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads SetScriptV1 transaction from its binary representation.
func (tx *SetScriptV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < setScriptV1MinLen {
		return errors.Errorf("not enough data for SetScriptV1 transaction, expected not less then %d, received %d", setScriptV1MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SetScriptV1 transaction from bytes")
	}
	sl := 0
	if tx.NonEmptyScript() {
		sl = len(tx.Script) + 2
	}
	bl := setScriptV1FixedBodyLen + sl
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SetScriptV1 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SetScriptV1 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

//SponsorshipV1 is a transaction to setup fee sponsorship for an asset.
type SponsorshipV1 struct {
	Type        TransactionType  `json:"type"`
	Version     byte             `json:"version,omitempty"`
	ID          *crypto.Digest   `json:"id,omitempty"`
	Proofs      *ProofsV1        `json:"proofs,omitempty"`
	SenderPK    crypto.PublicKey `json:"senderPublicKey"`
	AssetID     crypto.Digest    `json:"assetId"`
	MinAssetFee uint64           `json:"minSponsoredAssetFee"`
	Fee         uint64           `json:"fee"`
	Timestamp   uint64           `json:"timestamp,omitempty"`
}

func (SponsorshipV1) Transaction() {}
func (tx SponsorshipV1) GetID() []byte {
	return tx.ID.Bytes()
}

//NewUnsignedSponsorshipV1 creates new unsigned SponsorshipV1 transaction
func NewUnsignedSponsorshipV1(senderPK crypto.PublicKey, assetID crypto.Digest, minAssetFee, fee, timestamp uint64) (*SponsorshipV1, error) {
	if fee <= 0 {
		return nil, errors.New("fee should be positive")
	}
	return &SponsorshipV1{Type: SponsorshipTransaction, Version: 1, SenderPK: senderPK, AssetID: assetID, MinAssetFee: minAssetFee, Fee: fee, Timestamp: timestamp}, nil
}

func (tx *SponsorshipV1) bodyMarshalBinary() ([]byte, error) {
	var p int
	buf := make([]byte, sponsorshipV1BodyLen)
	buf[p] = byte(tx.Type)
	p++
	buf[p] = tx.Version
	p++
	copy(buf[p:], tx.SenderPK[:])
	p += crypto.PublicKeySize
	copy(buf[p:], tx.AssetID[:])
	p += crypto.DigestSize
	binary.BigEndian.PutUint64(buf[p:], tx.MinAssetFee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Fee)
	p += 8
	binary.BigEndian.PutUint64(buf[p:], tx.Timestamp)
	return buf, nil
}

func (tx *SponsorshipV1) bodyUnmarshalBinary(data []byte) error {
	if l := len(data); l < sponsorshipV1BodyLen {
		return errors.Errorf("not enough data for SponsorshipV1 transaction body, expected %d bytes, received %d", sponsorshipV1BodyLen, l)
	}
	tx.Type = TransactionType(data[0])
	tx.Version = data[1]
	if tx.Type != SponsorshipTransaction {
		return errors.Errorf("unexpected transaction type %d for SponsorshipV1 transaction", tx.Type)
	}
	if tx.Version != 1 {
		return errors.Errorf("unexpected version %d for SponsorshipV1 transaction", tx.Version)
	}
	data = data[2:]
	copy(tx.SenderPK[:], data[:crypto.PublicKeySize])
	data = data[crypto.PublicKeySize:]
	copy(tx.AssetID[:], data[:crypto.DigestSize])
	data = data[crypto.DigestSize:]
	tx.MinAssetFee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Fee = binary.BigEndian.Uint64(data)
	data = data[8:]
	tx.Timestamp = binary.BigEndian.Uint64(data)
	return nil
}

//Sign adds signature as a proof at first position.
func (tx *SponsorshipV1) Sign(secretKey crypto.SecretKey) error {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to sign SponsorshipV1 transaction")
	}
	if tx.Proofs == nil {
		tx.Proofs = &ProofsV1{proofsVersion, make([]B58Bytes, 0)}
	}
	err = tx.Proofs.Sign(0, secretKey, b)
	if err != nil {
		return errors.Wrap(err, "failed to sign SponsorshipV1 transaction")
	}
	d, err := crypto.FastHash(b)
	tx.ID = &d
	if err != nil {
		return errors.Wrap(err, "failed to sign SponsorshipV1 transaction")
	}
	return nil
}

//Verify checks that first proof is a valid signature.
func (tx *SponsorshipV1) Verify(publicKey crypto.PublicKey) (bool, error) {
	b, err := tx.bodyMarshalBinary()
	if err != nil {
		return false, errors.Wrap(err, "failed to verify signature of SponsorshipV1 transaction")
	}
	return tx.Proofs.Verify(0, publicKey, b)
}

//MarshalBinary writes SponsorshipV1 transaction to its bytes representation.
func (tx *SponsorshipV1) MarshalBinary() ([]byte, error) {
	bb, err := tx.bodyMarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SponsorshipV1 transaction to bytes")
	}
	bl := len(bb)
	if tx.Proofs == nil {
		return nil, errors.New("failed to marshal SponsorshipV1 transaction to bytes: no proofs")
	}
	pb, err := tx.Proofs.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SponsorshipV1 transaction to bytes")
	}
	buf := make([]byte, 1+1+1+bl+len(pb))
	buf[0] = 0
	buf[1] = byte(tx.Type)
	buf[2] = tx.Version
	copy(buf[3:], bb)
	copy(buf[3+bl:], pb)
	return buf, nil
}

//UnmarshalBinary reads SponsorshipV1 from its bytes representation.
func (tx *SponsorshipV1) UnmarshalBinary(data []byte) error {
	if l := len(data); l < sponsorshipV1MinLen {
		return errors.Errorf("not enough data for SponsorshipV1 transaction, expected not less then %d, received %d", sponsorshipV1MinLen, l)
	}
	if v := data[0]; v != 0 {
		return errors.Errorf("unexpected first byte value %d, expected 0", v)
	}
	data = data[1:]
	if t := data[0]; t != byte(SponsorshipTransaction) {
		return errors.Errorf("unexpected transaction type %d, expected %d", t, SponsorshipTransaction)
	}
	data = data[1:]
	if v := data[0]; v != 1 {
		return errors.Errorf("unexpected transaction version %d, expected %d", v, 1)
	}
	data = data[1:]
	err := tx.bodyUnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SponsorshipV1 transaction from bytes")
	}
	bl := sponsorshipV1BodyLen
	bb := data[:bl]
	data = data[bl:]
	var p ProofsV1
	err = p.UnmarshalBinary(data)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SponsorshipV1 transaction from bytes")
	}
	tx.Proofs = &p
	id, err := crypto.FastHash(bb)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal SponsorshipV1 transaction from bytes")
	}
	tx.ID = &id
	return nil
}

//{
//"type" : 12,
//"id" : "FwdhnHRFvFBJVhLMYXaLhsWoAiAhSr5wKAU5vr2nJWNM",
//"sender" : "3Mui4nRT4vJxX87qtATDJpWGMy7xbu4TeCk",
//"senderPublicKey" : "CEybnTzwKe5Z17p7ioinmNrJfk2gxrS9DoiSHeijQGB2",
//"fee" : 2200000,
//"timestamp" : 1546802026367,
//"proofs" : [ "4vWsT7KtaxHDyhqzzNWp83Ewt1fr1CJweW8gBtpqeQWQWHfmHM6oi5YKW6qgFSz5dVNYAmyAn4yvb3Qg9KjyenPk" ],
//"version" : 1,
//"data" : [ {
//"key" : "0357e6376f65d5f6b59acd4a5b509509",
//"type" : "binary",
//"value" : "base64:Z0FBQUFBQmNNbE5xSzFlb1ZjQ0x0ZTN5WmF1X0NkbVJtVUZUR21pT3M5cDU4aEF3dDNUT0JJS1puVjY1bUpjNU4ySUZxdDI5MmZoRHl4Wk45U005WWRSVkQ3S25sMmpqR0Vnazc2ZFZwdF9xY0NwQk1PUGRqT0hrZDFRRlZZLXJtRkdTWmZiWXNsdU5DU3ZxS2l2ekxycEVOTVk0T3Y3YlFUYlc5a0F0VjdRMnF6UkhtUkJteWo3bHhwTTRDejV3REtKXzM4YkNvQU1BVHhfYkJ5Vm9KcDVhMHNXZUdtZjBrTFFoaXBodnFZVGQ4cVFlbktNZVdTclJMLXhSNE5BMi1Bcm5qTnk3LWJ0dDZTSmFCbWFQVjdCS190dkpiZVFqV2VPenBrLW85ZXBuVFhiRENvc3BaeWszbS13bHV5T1A2XzZlb2hJNHZIbXNNREJrM1hrUGF0WUJKNURWTks3Qnh5c0FITUZZWGNFcWhvVXFOd3dJNkJ1bDltbmEybFJTdGFCV3VHUUhHNlZEdDVHVkFleDczZV9GZXFXV1hkUEhaRjRvM3ktbnk5eTNFOGRtQVo5RF96d3FvT204aWh0bnVzd2JnbGtYUHN3QXYzaWJtTWktc0xlUF95UHVaSG9YWlFndjJvM3hQcTZlSWhkMGlSYXhjbEdJbFUxLTBFNEZ5MGhJOWpoWWhNX3o3RnRfaWtSTnRpdTUwdDROSjRsNkdKbGZBLXVZMVpUaExhNzdzTmxfNkVUVl92TE1waWFGWlh3dTR2S3ZKODZVZFlpbG1uZXl1TFJ1dFUtQ2tYQWFFMHhVWC11OFhJTjIyZllvcWtGNENSTTBuYU5ySGZWYVZnWk02NzRUTG0tQ3M4Z3FtdGlnQ1JncThOc2R0cklNZC16ZEtxZXNzNnVOUzJVUDRYSERNZDhVSEpaTFJVYjBab2xPbC1VS0xDaHZiNW5Pemx1T04xRTRqcnllZ3gzay1mbzV0Z2xJT1dWb2FicWFnWE5KMWlCWjU0MmJCN0FGYzF1c3EwcWJkUWFFdkRQeXh4TFhrbnhQXzVRX1FIZWFlMFo4dXRDTmtwcG1uNlI3dUpmbkZ5WGJQN3hPMXZRZWg2UnJMS05oTF92LTd0WnREZlBnc0Fkei0wR2tRWnFHNUI3QkNSSU9ZTS1XOF8zWHdJZ2I5eUlmZ1JLYURZOGNBUzB6QzFiZVo2cHU1VTVUX0lvM00yZDktUkV3TG1BLTB0b3VHTUtSbTlONTktek13eDdWcnRfQnJBb2kyeTJUWVkyWWp4dWtfcGI3LW50NURxbHFkMlhkNTJqenJoVGZIbGhQdUk1Rm9Jdk1BZWdGdWc4R0tsTkxvcFZoWlFyVXM5NTY2OHJfdTVhS0dtdTlydVh0WHJXX3RFenNNdnA0WGJHYmVVaFhJZ3V5aTJfR0lEQmk4a242Z25SNkNOR1d2QzcxR2Z6aENSSTZjVG41elJTRlltTU44VGE0dzFmYnh3VTRISS14SjVaaEVkUC1Gd1RUZ1h3WDZsdnNmdVg2cXdHMHRaclp4MXpMS3NxckRLaU1WREtwV2ZJTDcxdWF6MFRuWVlwdi1xQWxuWF94b0pvY1lRc0pETkRraEM1dXZMRFltRHFBVTFpejhXR1d2VV9aODhRbGpHSWEwcmdvbWdyR19jX2g4T0txYlNYbE9GVU5BZGdHYm5JTHN4Z2NuTVExTlFVSmRlZlBqb2JsMU1RdkM0bjAzdTRibUZCTkh6NEFROTBkT2dwWnV0dFNoaFl4UFZUcXJISkctaFZVelZ6OG9nbVJzNXZONk82S1hoOEl6UkJzM1BGb3dncmJ6d3ExVjBvdmVKRGZCSUxNMDZvdHVnOUd2ajB4bFd2aUJqS1lMVmo1M1YydTQwM09GSUNvSFpRdGFoUkJqS1h4Tnh5YUNiaFFGMnE3d0p4SE8tZzZLa2o5Z01OMmxEUFM1Zy1jM2hGZGYxOFNMNXpwcmVSSGpvMmM2a1R4LWZWUzdVb0VQaHhQMDlwaXdUdU5JNElWa1RfX1lEVFhKOUZHRFUyYjQ0WC1yLXVlTzh4dlgyM0czNnlxQ2dlVzQ4clJ0ZTZsSmk2SzF1UFlfVDA0eW9HZkhUMmYzWXkwNWZXaHdybnFNbHBBTmVnWEUtV0lwQjhoY3VnemlqT2EyanVtSUVhTzV1aFdoRVdoNmZFLUd1NUR3OWNEUTh0ZFVXSEdhMEJoc3ZGbU5ZVmhENDMzLV80MmZVdnZNSmI3eWtYUVkxazNKT0M5SmY4ZWJoa20wamZONXBHcFNHSmRaUTEySzltRThjeWxJeDlONjljcm9JeTRpSDl6a0JyejVyOWM5QmQ2YkhrQ0o0MHNLNjlVUm52T3Q5Y0ZISGptMTQtQktvNkZFVERhM2pWZ09PdHhyWXVJQ0hueHJEX2tfTHlTRlFUcjhqTzZmYnZCWE5vck0tM09nM0U2MGhRTnpQNTI2Q2ozRTIzOWUtUkdEam0xdUxTSktpODBUWDdUZl9velBOWlMwV3lScmFPelBQQmNBTUE5UjhOYV8wVk53a2R5Z0o1RFZHUXk1MzZUc3BNSUJKaGFxMm1fM2poOThkVnQ4blI1UEw5d2RYRGF4dzh6Q1FIc1JPOVRrY0J4SmUzaU81a2thczF1UVdLczdwVDdFSU93M0hZaWJkeF9DcjExOFh6ZWF0OWZIRm5ob2dXXzllS3lUQWlVQ21TQ1h4YlhGUzd4R3ltdlJJYjdFM1A1MUNyZFBOVnB5U3k1RXUxT0xSWXpVemt1ZlEyelBWNEdBcXdURlVrNjVyTkVrei1pOGdYQWhlV2lkR2NwNldCOEtabmE5ZUI3LWRTVm1SUVZjcGNyemhsclBYU01YaVNWQXRpalhoQVFwejd3Yl91Y3VLall0QkRRLUNWbnFjMG5wTVRGOHJ6VmlOWE9pREYybnNYWUYyZVcxLVowOW10Q20yTnRvcVRoemdSenZSU3FEVE9IWk1yME9kRk11WUR3aVE2MVNuTXRKR1k2bW02dW5FRzMxaUpERUVHSU9LS1NZWXZCNWpiQXJTZmtFam9LUFJySGlKQlloZkRIQkZOUHBBd2djemY5dFNsQTVlcjZ6UF9qR00wejNxRjNFaDVkR0F5NTdBd2R5NXpya3NWaDZzTUp4QTNNbXJ1LXFfN0RMMzdVQTdrRDZ2NDhnMGNOS0Y3QkFsQzFMMzBRY1BDZkdQQWVzZ2N1SWJheEUyQi1mVFlDS1c1N050c2ExdEFLUWJKSTQ3THlBdjZaekE1NXpaWk8wZGMwRlp5WmxmTk9OckpEbmdkM1JkWFhNUk5NWkloaHUwQ2ZmSzFJVjNHWnlKVHlZU1M5WHZQR1lyLWVaejdPSjhYUDk3SXE0SjNGblJuYlJiUENWTDl3a1RPeF9CNk9LWnpBX3RPZ3pEY2lPemVva1NpM3F1OVdwNGh0U2U4Nkk0QlBRSXRla3g3RWtUbllmU3BZUllvSEdhb3YwdTAzaUxfSy05QlV6bUNQSjhFRWgwa1pVczN1WjNndEFBOTdpYmdTU1FSWExTUG14a00xMXdiT3g3OHJxVURmSnpfemlLUkFiWmRGRkJUcEtMWkJERkYtN2VXZ2VoQk4ta2hpZlp5MGhEdDBSTVdyX2FyUjRlc0FwcFVENVFvVDNQOXJ2T2VSU1JjX1htUzlxSXhtdEpxejYxd0ZIOGMzVmRHYkgtUFIzd08xeU9Pcjg0Y3A2S3pHeUY5ZDJZbUVLT2VpNmMwUGdsT3ctWmt0MlBVaWlNaDIyc0ZZUjFtWUo0dmI2NmsyeTd4al9jbHFMY09hQ2Zkc2hybl9lMktjU1N4dEVGMHZKUDFhQjhRRmVYdXdYNE95ZF8wSEVlTDdkV1VDdi1NLVM2dE9Lb1h6V3FSTGV1VTgwemxZc0RxSDhfbTB4YkZ4NGRMS0FPQ2ZfeFEwYS01blhlY19LOWlaeGZ4MWZaQ014bWRJeEtWMjJNa0hWc2lqRmN1UVJUdVBDR1J2b1dhVWl0R09ZUTg1dk9VeDVMMzQ4UGtxdzJjc3dVR0ZwWTY3NnEwdm5vNFg1eWwtSGphV1NXcUhpYjAza2pXR2liZ0RqOGRFbDZNcGlKVFJ1UmZkX01xQnFxYWwxUEwyWDBCRzVDSVd3X3lBcUxpZXZZN211Tm84d2E2ZU43dnl4SHFSazJ6X0swVlFaUEFsSjlMUzZaQnlJSjJ2ZEc4NlBZQ1oydnVCM1N6TEZDSlktY2hZR0ZxQXU2YWo4bWgyNnhjODlCQWs1REEydzB6UDlvVHduaTRDdE5scFVXdTVVd05VbV9ZaVloZFU0TThwb0l2aXByOEtKa0FlX3pqTFltVVdyaFMxRFVOUlNyUndfX3VTeG0zOE81QVRoMmtDNVBETzJtblU1Y2ZWR2p6M29IVy0zQ0g3MzhTMWN0cFU4dl9pUUh1T0dVcExsZUVXdldpcjFZeWlYeUt6ejVnZGoxUS13anVqVU9JTFRnRUE0M01KSlBvOVhiNFhqR0pNNV9JTU95R2xmN245YV8zaElhSnF3RUhUckNmRElHSEpkamFDaFNrLXQ5RjNVb1EwSkQzUzhqTmpZYTlhdzktTktJdG1kSjBMVTNxdHhpQlFMdDRhdGlOT3N5eG5xYlpTdEhaTUpDWWhDa2tZWldLREJEVW1rTkV5TkxrbjF0RndTUnBWaWRScjJCb29BcTFIdDl0Um1nbWZvMHUxdEZaaHJBOV9abGlFSGp3V2VtZjF4Vl95NW9JYUYzQVNIbGF5NTFQaDVBMVN1dm91clF1RFZnYklNNEhoNXV2OUVHS0JWLU1ITFBJd2NINkhCY1FjdVpONTUwMDA5Z1NBQXV2VlU5QVktMU8teEkwR0lCNVF0d3Y3UlFITVd6YmpISGJtX3NnSG1nUjRENzBxWGpsM0ZZTUpMZHVoOFNZbkVYLThoX0FuaHIycXpYdXNQdE9NcDRLWFdiS0tRdkVfYk56WVBEN0F6a1pfMUswa0VnQmlIa3BYalEtRkJyY0VjdGU2ZFpyRHVkbm0ybV9SRUNqTnNoRkhUbU04X1dnVVlEb0hzTDI0Ry1uYzFQSVBuOGtudDBRQ2hWODkzTXlYRUdvYUdaSmZ6a21hQlA2aVZwNXJ2Q3BHS3hZV3FIOEY2WmpuTDhyV2l2dkJHdzZGcnczaHhnbzBXaVRjVzlZY21sZkd1U0Y5bFRXeGw5R09QbkdBajIzbGZWSjhETVZ5bTdNbEVkSktOOVJVeDlvQTBtTkc0WnVjNkxUN1FjdTJWbFZHNUYwM1JLVzNyZXlGTVBwNmRXUl9TVEZpUGRNNTBTOFZjaTRpRElieUZ3WVZtWW0ySUFyVkhXOVJrN2hoQjIzSXZ3bEpwbF9DU0ZoUlZaeTdvOFBQLXRLdWttREF6UW1hMGc2UnVjYVMtTmlaWmFpLWkwWGxFc0RSVWFMSVRteXY4Ul9MRE5iUDh0NG1XelRsNEtiT1FCWkxpVXpJR1RfTTVYaXE5WHBkdENxVjgzS3VhZG5nQ01fUkMxeWpUYWFQT0pTQU9vMnV2S0JwZXNmU29jZ0xBV0N1anVlVUVtUEQ5OXhJYXBTWW5kVGtkbUNPYmoyVTlDOWdOWW13Mk01TGkwQlpWcmZ6ZHhtLTYxNF9XTFJKOUk1anlFaVZUM1RWVW1LZHlVblhCUFdTeEVxNUhFNEtFWXdFdDRUYm5pcEJrcUN3a2RVNWJXUl9VaUEtaW96RnE2Wkk0SGQwTGpMUmJwbUhHdXBhX3ppS3RXVDZ4Y3BzRFdDWlNZZkRWYjYyc21OTU4wUVdKT3ZldTNJVTRsY1B0V0xkU3RTTGJYR3MwOC1HVnhDTURLdlJ0VElyRjl5bE9QcmRScWtDRGozcWtZaGtuRmN2TlF2MWszYUN2ZDhpOUZmcm5fTDRXb2dyOG9lUDRaWVJ4amExWk1LVldIc0s1RU9SZWRDaWlubHlzQWpKdzlxd3Z4WG1wYW5lWWZvNFBLSVpmdldIYzFRTlZVUEpWZ0N3QldGNWY4ZXNSUVcwZ0Y4U243akVubGdjRkx5bkMzSVlpVUFqVGpWX2pWVURjWm5uTmEtWVFOdDVQc2hBVVdGdUlLbG0wN3pueDkzTzZoT3hRZE1JRnNsVTZYRUM4VDU3NHRnTTYtQVdhVGJ4V3dGU2xfU0p6QUY1YlpSZTNIVExxQ1hKNTlreEhkNEpsY2lIOW1NcllhMjFfUUE0enZPOEtuNGNveWJsOVgzaFlKMzlqUlhXa0FFSVB0NXJzcERzaTVJRWYwY2xxNWM2enBybzVXRlZGa2NjZkQwd1htMVBRV3M5ZUlkTlhlUkIyZURvTExKcmpzZ1FqUkFTZXNKUVdGSzBWT0hLSUhsRGpVVjBYTG9EQlVhTEZmSW5mS05sZmI1X0c5UHJGb0l5Ukt6RExxUDVTX1FTd2NtY3l6UW1yWDQzYXZSbG9ncXVBTXBOYVk4RGt0clFvSEt5dWFFamdWMk5JOVAxcTV1X0VXVGo0UjhINXl0TEo1V3FOTzRxZmpiNnhpNW9GeHczeFBmR3NNdngwcHEwOE1JQmtnRExJYlRHczNVWHlfdkxhUThrNG0zVFk2WC1kUkVwSXJrN2lEVDhGOVh2RTl1Q3RPYzY2RExGdk5rYlZNcG1hREhyVFc2cnhmYmg4NEJZVUt1clJnUGtWcjFieEEzbEJ2bUFSS19oYVB3UjdKT0x5V2E1QTBhRzl6WlZSVTZfQkZGNlJsc0Y1Tm8xUGdJY0o5WnpqTnNnY1ZNZkFkbkZSWXBTaVQ0Y3J0UXlJNldOcGpUY3RXYnd0a1BrNkpuTDJiYl9Db3ZxMDI2TktHMkdYUlVjUTgyeXNUQ05DTXpiQTNQVXFiZV9WR1lxQTRrczdOVDN1VEF5YmdzNlR3RVA4SWVhcFVIUzdhYlBzY1c2VGVSanZNdnRfVFliWWhHaXVOa1o0eFBjVndFMDIySVNoN251ZXU4ellKZ3NWMHZZQi1kLWI1WUUxN1RiRExhdXp0d3NkWFlCWXdVdWctdmU2R2FJcXlnZEotaFBBRlpkSWVVZDgwcldNOUo4YjFyWk9xVDQ1bUpUYzZFNEtzaVZBQjVCRzh5alJqSHY0dnROQmtYYlpHcDhpWFdzR3dLSWJOamRwdE9ZSkZxelFoZ0ZPOHRDbzRpTUotQ2ljaUNRLXdTQUxsSFRaUmRZTzlYeHd4Zy15eldaUjJFU0wxbHI3dFFEQ0R6RVZYTnBiUWxqaDZuTlNLd0JUSHhOZUpUNjRIN2NMbXFUUVdpTmdGRUpmNlNxZnByYU4xVnQyUVNraEdkc2l1VmRkVWdSR2t2MHdzcW12S1hPdC1Td1pxeHk0aEtkN1lMal90WkFlcnVGZjJUSFdYTFFsOFVxX2xhaXZQVEU1ZFVaQ3BZemlRSGFMd2ZQUHJZQkFydWEwMkNqbk93Y19DSldvcl9mY19uOVgyaV9EaDVzRGRxNGR6NjZtVUhfT0ExaktLbzJ4ZHVzUjNhMVpZMi14aWg3cFJITFFNLVlqSWtyTUd4eDRXS1EtRG41dGdud3hLcFVUSS1HRTA1bkdmRWVDQ1ROV1llSG1PVGFUWngtUHh6YWtfUlVCQk51RmZGYm1IVWwwVXRWNHQ5OTVRdHVuaWNYQ1htbmtHNnNkQjBFVGJCX1VCLTgyVVV5WE5LZnJVcV9MZWdqMW1wZ2ZTNUh3LWdWZjE0ZUQzbGp3TE1QaGpOUnRMaVEzdGZmTXl4RUdkRFV6OXFMb3BMX3ItcEhaM0tUc1pkSmp2MmxXdEgwT1dHYmlRX21oN0NnU3g1ajV4WEtBM3hPQVZsRktrWWNfczB6QXdOQzRZSlNuZWZYUnZHczNzcUlUcjlKS1ZxTUZZNGRFMXJrcGMzNDZxby16eGZucjFHa05XZVI2RVNXNEtSWURsSkd1cFlTREc4S2p3YkpSRkQxTU0zd01BT1I0ZnViZGpoMUhack5RV0pmeDdORXgwcFRZaF9vQ0JOdGhrb3FfZUYzZk5jZ2lEVVV1WWhTUkJrZk1rWXBVSFZVRTlUblJ5b1Y4QVAwTFdUT3k0SnBMSDExWDhYRGlVcXlJNVh0bmcxaGVzbXJxRmh0T2NjUEFCNnd3Y2VQUU5iZlhFemZXYmNvN2ZKd3lacWpBaDlqVTF5WXhtSGloeEUzVEh2NzVhRmtvS1dsazVNTERsRkJ1Rk94N1JaRFh0T0pBOVpWLTRDYnNTSXo2eEN5YjBKTXVXcmoxY1pkT1V6dmFobzFmaXkxaVRIWktoZDEzV0RyNlVOa3F5UmxZYnltOXl3RzFLWVdCSzJ4NzBuX2xaZmlGRVpJdnBULUozR3dNYTdZUV9qUDZKMzFzTVp2S3FycU83ZGotU0steG5LLVBIbFdDdW95elRDZjBMVm5ZSWpLRTczcFVPM0h0LVdlOF82bTVuZ0FLRUM0LTRZbm1yQkhMb0pQT2ZjMGtOazgxY1R2RDMwc3pETHFkTEdXOVRiaU5mcExIZ3VpNDMzRzV0NC1vZ21KNHJsYmtxWnB0ZmRUWHA5aFBjVjFLMkFJQlYtRnFJbTBBZHBmOFdiYUQ1bjRpek5OOXV6a0cwZW5ROHFXMnAxUGtVYUxWRmtEQ2xjRy0zTkExSjZQVm9rNG9sOE9tUnlwQzQ4eXZ5LWE4Z2Z3U2h3ZWlZUGdIVW15MU9CS2c1bnJkOUtSSG5KbWdad0pjZDBQYk9Eem5OeFNabzc1c2ZiYXptLXNVVUMzeE9CRi1qMWJzc202THNYMGFsTWZfU0hNNjE5SzlleEZ5dUxHa0pRbzRia3hLaDhJanpWV00wWjBxRURKUW8yanBLaFlBVGZoS0JZWnBZQ252YlU3N2dwaXJtYWhqeHkzYVRSMjVZUHlhNGQ1Wll4RHNlakVGMEx4bzdabWJRcDcyTlhOQ0hyNjBvQy1TRllMME1JSExpTHJiVG5XR21mUGR0cGVnMDZid3pIQVJtUHBoQ3gtcWV3RUd3WWxfNjdfOFBtMm5ubGJTaWlpQU9rRE5uY19McHZwVXZNUkNNUzI5aXprODhrYVl3TXhBd1JNeUhrTmt4LUZTbHpWNFVzMjBZaFhRRkJianRyaWplSXJVV1BJRnVjOVdYQng2LThnN3BGQjNWQWFweElkWTZtYS1odTlOdDkzTW92UmdOWlVJcUNVVlZpMDd1VTJWMEtDbjRnWmtxWUdmWTBnXzlWdmZPalVOcmoxU3h4U2Jac25feE4xc3JFSmNzcmpDOXZJNDl6VlhvRGdaMXRKZHhoT3d6VWIyR1JGWkV6OGlqYnhSREhRdXNRU0gtUFdIMnFTLU1Wd1p1eC1VWTZUTU1xOFRaVGEyeE1BVGpvNU93eGZNS1l4N0hBQ1hOaU5lZk1NMm9tUkpjVFl6WDRQOERmdWM4Slo4bEtfVF9zeVVkUmtwdmo1M2UxaElzN04tajAzSjNjcUQyTTNrZ2lDb3U2dnNYWUNfZzZyd3JTd0c2bENqNTQzYXpISlppeC1WanJNcVMzVWtfSEZidTNoVmw0R1hSYUt2M3Y0YkJETUlSVVpzbnZLZUFJdGIyU192SXVfMThLNkU3NzlnRGpHVTZnc01VbmdDcEdRSy1RQURGZndOSDhnVXlUZXMzWVRuZE9GYzZreDNaVE8xX3FwenVEa2J6UWtVdHpqLXBVOEt0QjBMSHQ5Y0FTTEh5OTBWM3lZekdMQjFPSHI0NlF3NXBOYURVMkJITzRYVzVUN09PWlBqVDZsS0puYVg2MUk4T0ZGT3ZraEZmTlBmUkJZWkRwRkNKMl9ENFBqUUJ4X002RmRqQk1CY1k0OWMyUlhsNkotOTlwTXFvelIxM1JiMTg5RGhnLTFBNVBOVEo1ZHN2WVVVLWdrQnVGdWFnWHBRT3VrOHFiYlRXdjdTY0pnbVhiblJPXzJEMEVScmpyVFU3QUd0MDFyY0FOOUM1eHZOeVpYUUhJM3RDT1JNaWFlQk00TWRlcHM0dE1MUHgyeE82Tmx4bTZlZFVpNFMzSDdzLXVIdU1ybHk0UE9iUGVLbzFoS0N3QXF0LXpsMjRJZWcyZHFFUXBtY1FXRW1ReXpvZjZKWjJPZFJVTUxxOE9tNzlkejZzbGFQY3A0T1dXV3hLclYwYzN5dHdpUU01aUR6Y2dDS0tfM2ZFY3hHQ0hDT2R2NEladngyZGNURHdqb2xrbTRueVNjYUpVYWplY2FRaTJEY3BzWDRvZ3ZjbHdlTUJDWWt5dzhnMkUwR0FoN29zQnJOQW5zdmNhR2RYU1Z3eURld01kSjdZRVZHS09VWm84YUx5YV9vVzlEUktmUVY3cUlhbmNPNnVoVEdvNV9oZzVBeUV1MF9fQ2R6MWJnMVl2TlB0TU5EWUpEbG55WnlNYlNTa2FWS3pfSk85a0dxYkpraDdacExZSUtYOWlLd2JSU0FMemw4dlBiX194NjhPMi1UZk9RNzhsUVF4NHNGUDZqbHNFT3lDdzF5T1pvcTJ6NjNuYUxtaExuSmFoZUFPXzY0dmdnTjRFNzlBNS1MOXlUcGU5UGlJUXN0Ny1IZ2xFYXFvNC1KdDNfa0NreG9rOHZ2NmlkSDk0NXpINXk1dlREbDdUXzktRlk0V2dNUXJ6bEZPaHhzbFdMYU9aZGhzQzZGMkEyaUpTZ2N3MXNtbFdwWGhuUmQtam40a0tqdEczYmxxVExLUVlnSUVHS2RCS194ZWJ2Tk5tQXlJRUJWcGM3ak5qc19nZmlOZm1fVkRBVk1WZTdZMl9WYlZjUTVqRl9HdXdNZmpCQS1PMkpmNG1WQ2hDNXZMQVQzVVB2VXcxOFY2bm1MQVF5Q3dablNGY1Qwdkk2UmZOcEh6TUV1cHhnZjFOeUhtZGZRUy0xQnVCVEk5Rm9yTnZ4T1JhNkg0eHAwdFo5TUp5bldYbmkxZWQ5R3VZbWE1aUY2RjVtOEg0aW5Qb19CRGRaZDFIT0tsNlpva2U0UVdVeF9SUFVnWXg2LXM2VzdLTFlnQ1hFZ2ZxdE42MXdpVHloRk1oclRwNllSUTh4VHFkNmo4Vmt2U1pFVDZCUWx0bXluWDFlTXBkaHRCdHlrREpOc3hQSHhvU3UyYjBXTnNuakp5ZlpLTGlGNlJzb3EwQ2thZHdzLUdHZkJRbGNreG9ubWlmcUkzQTBGZWR4eDFkb1hDRmN5WkZ3d0hZSEQ5cDlYMjNUOEtKUXAzTzg5bDc0YmttSUIyN0tlUnNDQ2p4QlVxWnNYMGNxSEhveEYyYWNLY3g0TWRIM3gxNk9xNWZDSTd1dnQtU1lwdWc2RGZZNlY0SVlETTZaZHFVTG1YRjhuTHlpUmZ2dXA1ZW1SWFNUZDNPR0hRcFBMeXdkSlFfS3RSTzgxM2lJR2V4bXRaOGhDUDZuTk9lVkFRTjRhM2gwR1FPanl2bV82WUdFMU13LTJ3MFZxaTBGb3FwSS1rbFJrR2VvUW5QUDNsTUtSTm9ITDZ1c09jdGVXWVl5a0JpeUpONnhMUlBlVFRublVkYndsV3BlZ280dVdJY1lVVUFMSTNhVC1tVVpqM2dsUWVzM0hxQlFLZmRoa0F5NU1mRXBJcG90TFVLMUpld1FOdEl0WWJ6WFdjMDhQT2Y0NzhKRDBUWk8xcE0zTnA4VUJEdlJyQm9kMXVOTkhtOEl5dDFZREpXLXFOV2dhbTVVb1BKcWowaXhoa2FadktRYkhISkpoX1dKbXZrdTZqc0ItaERVNjVfbktpdkplMzZPdWkzRWZsczJ2VVpDRHU0WUgxRi1hYnZtRVd0eUdOUXJhb0VuUHZsb1hpaS11Skk0Y3lmX1FJYmJoeUxtMmUxOHlUR3JINTcwLWV1X1Q0WlpfM1FtRFFteGgxcnNxSjlVYTFtcWREbmEwdi00Sy1kVzlDdktvWTZ0a2hVSGc5YmpCaWh1Z3pGQlFaOTU5VTM1dU1jNW5saWxteXNmSTFIdktBdkFiQkJBdldiZHI4ajk0NjBRaEM2YTRUZGRBb2JBOTJOeHkxSVRRN2dCSWhrUUx6UlFyd3h2NTdCRkVWMTdLOWNXUHVnTU1DeUZtUE9BZWRkREwzX0VGX3BzcDFKbkwtbXAwc0lOal9Hb3BqOTg3YUpUdjhmRl9MUHROZ3FIdlVUNktXZS1iQ29jeDFSOHlVM082TmNXQjIwSE5PWlA1ZDYtMDVuMFdpd0JNT3h3WEtib0luZnppOFloZlhmc2sxeUUyLWgwdUVYU2NnR25oRnltZk5TcXJfQWZMRWJDVUxDU1FvSzVRWnluTWlvQXZQY2kzYUx1R3RSbDZzbWR4Rnd5aHExd0FZUU1KQk16bV9BTkpFSnltQWxKcTJNMTVjVnVwMzRLX3dHU1gzWnJIc0ZiZFZYcnRBdi0tT1BtR0dLVEx2UEFHU2lGY3RHNTUzVHRpZzVPVGRxMXl2YW9qS3NleXhXOXU4RzAtMThPTmlaMG1NVFdURVBoRk5HdkVrZ1plbFBRbjI0WnlJRUl0VENsaHhNdDZtNHZNMHpDS0xSVU11UnJXZUJRM2dIc3pfbEJwQkVNS210cDhGMnJ5bXdiYlZqRmstR0g0MEswWjVuZmNadWZPUXpXWGo0dXBZRVJqWTlOcERWbS1maUdfLVdoMFB5dTFpd1BnX1ZwWDZvMkQzMmNvS1p1NjBoNVVGX2JYeVlscnRYMkpVcW5LYVRBcGFtTXBtSE5QZkJ0eWo2S0JRUHJDUGxCQTRsRE9kOHJyell6UlNwdUJxRDFDOWE2T0ZGWlBxd1hSYUVrVVJENTJIYUh0OWxRTTdzMm5Sb2EtTTZWbkotS05VeEQ3WnliNDc0NVZBMTNzc2hEUmVUODJHQ2FNQ2hvcGpkYnJzaXRCejZ4WmRDb1JFYVlpc3EwM2dCYW5HOHFuc2stNkJoN2d5Z3VrRE5CT0YzNm1penJaZDNzbDJHbFBHbjZXYVNEX3JnWnVRLXRWMEprYXpVUFB0TjdCdFhoQTh6dTlOVngwT3ZIMHZPYWVsTGR0bGJvMGozMmdsOGpBMERYbnlpMkNrQlYtTzBTMmg0Tkxickh5aDliLTZoQ1k0X3ZKZ0VOUncyUWUxOEdDckwzb1lycGF2NUFhOHdiSExSOFRNN0V1ZE50bnl4Nzh0b2t6MW9CaHRaMWdLcVo0ejg0Q0l0THRxR0d5aUxhY0lVMThXWTVYLUhhVXN5Ynh2OWtpeEIzTW9PMTRHWDlHbzhmeGRYbFNfdFROYldETkhDZTZoZ290OEJrZ3poWVVZaU12UWpQbUIwOEhEUHBpLXJscVltQ3dHSlZSRkp6M083U25sRkVkS1htbXFjRFBkQWNKbXB2U0FhUklkSmFWQ29XSlZlQl9ZajVQS1BJdnZadktNYUtTcmtocjBzYWs5QkRGbUg3QkIxSUw3NGJzZzMzYXVoQWNZT3U5SndCVm5iWlQxbGpVRzc3OXR3eGU5TlNLei1WRXJhc0o5U3ladTFpeDZzUGZ6MG4zODVzc0xDR0hxcXpNSkJJTGRibUtRcVFBT3dGN3BNaFpWLXJzNDhOT3R3cmg1OGNwMmJDdjVlYXEzeTJkWjZyN1ppN3UwWW11U1FaelVmY2l2bDdPNWhrekd0Q1hJN1RyTkRWMDl4R3k0RzUtRE5FOHFsZUJLY0pNTXdhZW1NSHlra3RSV2h3a2ppOUs0TVVXbUIyYXBWRmhrY2xKcnZvVzRTU0JQYUQwNTR3TlpCUW1HS3gtT09UOVlMV1laZzBENlVFZncxMGpCOV80ZERzd2dJRlY5NWpmdldkdWtGZmt5YkVKOFM5bEtfd1QxMUNYQlo3MHJfNlEwZ19ndTZyMXd4eFVwLVFsb1g3bXhwZk0zWXJUd1dtX05mSzI5S2JMeDFXc2pCVjd2a0dXYjZKZ1IzYWFQWjFBSDVjSUtQZzRRUUhyeWkyNUNsRUNsei11eGhmRlBldmJYUWU4Qkd1X1AzS0pGNGQ2WmtfWlNjNTM4bl9vUUpiQTI1RHYzRDNUMm9maHJLdXFKSmt4UFRZVUs0SGZESlhSWTV1cWhQZDlieTdZTWptYkNBU1E3dUtzVlpnWGZYc1FXM09SS1JHY2k1cnl2YnFNanFKUjRqTWh2NFIyS3JKNUNJN0dObnhwTk1Id2JBMlZlLUx2bDgzWDByLXE1NWtfVGpMVlJ4dy03UXcySkZxd0VVYmVab083ZjFFd3U1cHZGckk3enlxcnhRZjJkcFdoRGtvNExiclRLWllSekNYRmlJdHJjSVhxUGN1YTBxLUJrWE9sczNHY2tSSC1lZGxJVEIyNWd1R0hiQ3lWRmJTZ0MxUTNhVDFGWl9KWmdsM2IzaDZUalAtX2luVUtzNUxSVjR4cVd4MnpuOFZ0MVdRSmZqRi1qVFJXZ3NtQkYxa21RU3VESWVReEV0bmdnNDZZV3NjeTVaXzh1QUNLcUJETkx0ZFdYV2NueUo3SmFGTVRoQkF5WlN3OTN2blJpM0J4aXBvRVlYS3J0TTFuamg2ZWdtQUFjMkE2QXpuM1ZTSkFtc2RPRmp4YXhLdkNiMUFWSUtiZFBXMFJYQVFqc05BY0duQlViTGNIa2RXVldaLV9mWlNteUhnMkJHZ3JlbkpPbjA3bU15M25UcGVNQkp1TUhVM1g3ZGw4OFcxWDVCRzdXRXp4T0RQcGptUk1WdHFSZThOVUFzOGRScm9zZW1VTG9KVWVDRW13cS1qYnZNbmpSaUIwM2d4NTM0MXREdmt4OUVDQUFucjV0d0c5cWZISmM3dG9kdVU4Y1R4Ri16dmVKVFM5UUVMVnNXakd0bkxqcUticFMtYVZPVGhlZlRTc0EzMXREc2Q3aEJVdlEzMTRDWG8tZWllRnVwWERJQzRQVzN1aVEyandEc2pId1U1VWxlMXU3ZWJHRVZQSm93UW1aS0gwYmNDQUlSV3RUbDkxVFVHb29lQ1Y4enJmUUdYaDQza0RTX3UxcWt2MW9zZFZwS25DQV9XNUNZVk0tRU5TLVBJbzBmT0JsWUlEUk1ncE5fcjVKZVdvNjlzXy1qT1pOSzNYZVVkejNuRmJOeDZUQkhveUtJejZDOEVNME5QMlpfYWdOa0tDSmNSQ2xrd1NrMDl3aU9Ha3lCNXFvSmVjRkd6bWNDMGxpV2JwU2ozZkxxYkVPTHJsMnBnQ2VqQnR1eGRsNGVfMVNUUlhKeGJvVTB3aE1KSnJNVVRXUWdxUU9qTXFGRWdJMTltdGsxTWpiNHd1Y2E2SGNJS3A1aXFaQVVsY1U5cndaNG5ON0U0MWR5aVNqVjhyM18ycFdqVFZvTDA1U1pCZjRoUFhpTXMzekl0U1VEUzNJdnFvck5GNHhpQWZ4MjdDWU1WVUoxbnZOWnJ2eVhOQlR3amJlRFU2UVZEang0dmRmbG1oYldMTXNuSm5qRjVkQi04QmVCemxUM2lWenB4RFh2NGxZczQxOXk1aTNFNHZYSnRkckxJeFFBUEtLX1BOMnE2ZE5TZG5KWFVsTm9MQ00yWXB4Z1JNbE9NeV92SHpyRnh5dFF3eUt2NmI4Tmhsc09Ucm1xb0NrbDdzOVBCb2l2QmFRLTRZTmpROGRVTWd5RDlfVnNfZC11cTVOTHptXzh6Tjk1T1B3ZHg5NW1fby1HcmFVaGk5RnBiYzJsdDBqbjUwX3FMc0F3OTFOSll3YmxvYW1zU05hcDgxd2F1bzRmTU5VNjA5M1ZqSUliSW93TDBERHhYUmhXcEF4WTZUSUF2dFJyS1kzdjFLM3NQampFU0hoZWFJNTJoVlJ4NzJFeTdzNGVhblVKWkZXZTBERTFBMk4xZjRpX3ZJVUlIaDVNSE11Njd3OFV3Wnp4MVItWjVvd19oNC1BR2pDTGhKRUdCR2d5bTFYTk1PYTY2NTJuTVJfN1pCY1ZvY210WjI1aE82bjFlbDhyM3FPdEZpbUFNVEhWVnpsWEFUN0ZkUjlkNkFSMmdHQ2hhZ3Q1dmNzXzdQeFdtMzlwcUhYczJmYTlyZndyWFp6VnJ0VS1qVTY2UGI0aW5WTHkyZVVGVGFiVkJHR3l6VjVuejZLUXhsOHZrY1ZTNk5GeTkyTDZiaEw0UW9na3dJWExaaHJ1ZHZHSld2UVJWYmFKSlQyNFMzbXQ4aThsQmhsWjBEbENNeEQ4UzJQeUY1M0ZkY0dicGZzUnJCUEt1YUtRV3ZzYzcyZkZTcnJYem5NUTNiZm5UMjJoU003RURBWTkweGlLMV9qV05DcDhZUXJCNUFFS04tckQ3SHZzTjc1WXpqUDZOWGcyOHBsdHVQNkUzWHVZVktLMkJLY0VQeFNhc2tnVjJlbkVadlQxdlRiRXZhdElYZDhZWXhOMUh1MkZOV04zMk5KaHVKYnZablI3bzZNdU5fYW93SktmeHpncHN5cXhSSEFmLUpHUEhMVDV6X3pHTFVDaF9IVU1vTXhLSFNEb1VFSVRFeGRCemNOMWRoVVpMTndqbVo5MGlJeGtYUERjcWZBZzNwUWV0YXhqN1NlOEExSDhWSGN5YzM0V0R4QWRhRTZLUVlkRXBSc0l6cXRvV1liNlZMTFhlNUpXU1RtUmdsdVBtdHVKVE51MGo2RDRLS0o2dDNMeTh5b2l4UEdadG5aeVQ2NzFnUldJLXMwRjZoY0k3UkVhaVZvMUtFblJ5X2lSYWlHMnliaW5xMi1nZjZrMTJPTkxWeXRta3VqWmpBakpHWC1NWUpodnhrSFVZRVFtNmJIb0t0V3FoWkFqejhzWVdWaDZQN3M1TEZkbTJMTnp4NHVyeVlEVjBZWjZ3SzJfSGxZR2tzMTJSc2g4NGVEd0ZXb0pNOG9Gbm1LenhjZW92OVdjS05lblVMVi0xRGgxaWJ5aW4zR0V2NUpXWTZLUkZyX18wQllldHN4VUs4eW1tUlBsaWYzNWdDTnJOUFdZb0VaZzZIMkZCZEVjczZXOU5OQVkwOHJhQkM1RHlkYWllMDROQkpEeDNzeDQxdTY2VGVxM05SRXBoWGEzeFZKdVRlMkVyLXlyS1ROdG9GM01MMDE5cG1hNElHcW5lSDVhc0VFTm1LM3FiSTl4bC1YcUUyOHprdER6S1RZdjVfWXkwLTV1SUJQR3lOQUNtSHR0bE45c3loQ2Y0QVg3M1FBM1A0cEJQZmdZMHdrNnA3NU42VUQ3UGRVa24yQmY0R2lvMGhZX2J3dFVJZ3pXM0JRZlNlY2k1ZEI5ZjNib01mMFBZV1QyQU9GbkhKZkdIb2xERGsxVVRNTHpYUm90REVrLWZPY1o1LVRnNHh6MzlrcjBRNkk5bEc5bmhmQk1KNXhaM2FsNXRUalBBUWZtWkszRFNsQXdia0c4U1h6OVMtLWkzbkZKOVcxdFpvQlhSWFItYS0wNjBNZWJFd25CRW9fUW1ZcHBSX2w2R0hNa2RVMGtlWFU2Q3FYSXI1NUYtdzMtc2VnTjJ3b2pZcDRtWGJjcllKNENGR1FDTFBGVVhqS3V2WWJlX2NIVEFxelhnbno3ekJjakljOUNhbGozYmI0ZjZCc3JxbklLTUg0b2RlZ29rQXQwMTZWMk94SVNTVjdhTzRUWm1GM1o1LUlyNnlsRGVqQlU4RWVfWWlWZzQyY0x1U2dkQ0lKRHRFeE5VaGVqOVF4aldyU1hDbTN2VTNxcV9ncjM2RUpadjN4b1pOWmEzTFNDcGRSU29zV2tQQU9nYncyQWw3S3VjSkVDcFhEdnFYbWRTcDlRUlZMWXZfSlQ3SmtTdW5jNE1nMWpKQzBkNmtWQUZyQ1FLU3Y1bU1yLVNVYWdyOXpKSkZoRzYwcGIzdU1FTEdMdWdSclYzUG5lUWdlZF9xb3pjOURtclRVdHM3aUkzVDZ4b2EzZnpUQjZLRGxEWTlOQml3eFA2MWNDX2kwcWExaTByeEZvSjBhRkp0V2NFT0FHNjF2WlAyQ014N1kyQkVNRlVBOEdMTVhqRjZEOTczVW5WM1RiYTJyMEZnOTFJdWExLTFyQTVkdl9oU0JlUFI3ZEx3emRuU2ljcGJiZEJ2OHZmY2ZuR0RrYmdodlZvamNIaFNXZHhxcTl0Q3pxUEFjVGlrSWNmQnpvc2tYTnJPYTYxMWZkYUtmZ1VwaVMxNEtwdjJOdmZyYmdxdUU4NlhNMFJFazNJSDBqcGktdkQ4R1VtdTA0UC1rcXpmMG05Ny1DMEJqSURPeHltTW01aENnNWlsUktvU2xFTkI5QmM4Tmd5TThBdUdvSUg0LUZ5Z0Nub2lkMXZnVTJxQUtxZGhTTjA2NEpURGQ4QzFKWXB5Q09MdThremV4cngxOVE2TGRoT3ZjQnFUOVJhdUtPbjBiU0ZpZU82ZmpDWmQ4cGRTQ2c5d2ZWR2NuQmtSamstWUxCd25RMmVMYWU1WUZ6SEdaWDhUSFhzbnplQ1E5d1YtYmpCZzI1Q2pHUzJzeWRQdmVQQ2JTd1BDU3VOOUEzeFpQdGtpekxxUFI3eEFBaEp6WVpTVUFmcEZBVjJWcVh1eGJfZHk1LW5BQWQ3TTNXVlQwbVFkRVhnMzVFVks2cGliREhvVG9RbVpISGV6RG9obmJrZzEzblpIcHFab2ZLWmNzNXRzMFdHUDZfV0o1Y3gxei1wX2ZVM1JOYzJhYTBvTE9Meld6cHE0Yk1hd3loLVB6clBpR3BOcWFxWmxhN2l0VkZNdUpGQTIyVXRoeDdWaFVRWXRHSWFVY2pXMzFCMXJuaWdGTHE0QW0zaXBBSUtENVp1OUxyVC1lNk5VNlZ4S3d2SzM3b1NINEgySzF0WW5qUTV2M1BRdkJKcWlLN2Y3LUdrdkxzQjdpMjZUMm5nTFJ0V1JaSF9oRGNoNHgyMXdFanYycllmSlJvbVIyMXlMUm5sd210TDVVZGhWN2J5UXEyWjVYNGJGX05KUXVYdEJhdDNCcE5xcjYtVlBJWUlXREh4Q0JVWGdEQ19mb3JaY1liUUJEU2NhLS1wenN1YnFFNnFIMEh4WFJMZzA1TWR2MDhQbHFvclVkTC04enF2U0JyMGFtTVRjZmVrVUE0c1RBV0JUVVFJR3lkNFJoRFRaUkdoOUpvaWVBdkZXakQ0YnI1eTBxRGtJRzdYZDFkeUtGNVpva284d25GTS05di1tenQ0T3ZSQ1VRejVSM0pTQ3ZwX2JENVh2Z1VlSG93Q25wRF82ZE16R3lZUFl4WlZvWm53RGU3eWd1VVBZWE1MZmNuc2Vtem9EZkhjX1ktZ1NSdjlQQVhCMk1GQXpzTEJYTGNZcmdpTHgtVXpZNkdmdEdWa1pSTlZHbGV6VzVZZVQwanREV2kzOFdyQ2xoUG51LWlLQXZzcVB1T19rcVNxQWMxalNQT1Zsam9uNmt3eWtmQ2tONGE2Z1dfbk9YaDIyQ0JuZzRyUUpIbEkwN1FsNmVicWwyVVNnSlJna1o0RHJnemhpR1E0cnJNRTRBTXp4RmFFczFDZFRiQ0cwZi1FRzRRbEl2dzkwbEhaQ3RqOG1DT29taV9NNWhqX29lQ3ljZVc2OGZJdHowd2xLRnZiLTZ0QXlsVkQ4anlNRUZRMEVrYUxOaDdGUGNWeGpoVzhVN2F5bkJZUjdESGZjVUtyNUM0UFdNRGNxZ0s0ZTJnN0VmODFiMWhWN3ZrV3JqOENFYUV3RVFWeUJYREZISUYtMm9XNEtyWXhBdDlDcmxkQTcydTg0T21lM00xQUdBd2FfM2lPNnlZSjlXYTVkcDd3WFhsS0lhZ2hsdWkwLUJuRERDS3pFSmQ5ZllrTmtRcWc3c1RuQUNtcDdTTjJfNE9uMlRBdlFrREpsTmllaTBjTlgxbEZVcVRsdW1CWE5wczdHRXM3b1NHMW9MUWdTbkVMNEVoZnRPcE5mMWtaM0pvSldET1ZycDJzem05emIzeDFsVXloeVdvOHE5bE1wY3dRQlVpMERyelhWOU53S25KMjBXcUJMdkh2MktPdUtZWnpoNW1iOVpIMlhXdFVrbm1xR05zb3JpeWtDTFFsOVVxelVxOGR4LTZ2TTBmOGV0aFdwMHVWLTdZWkhMYlpJUXVCZi1RRGVqWVdYTVoyaUZaamZNS09CUUhyamNJT3lFUVpod2RteVRfNnFsa0FiSGVWdzlzRndOend3MlZZQkVGU25hNmpGeGlSTkRSQ3U0MEU4cm5ranhlWFlmTHBIR25najFyd3RQVV9EaTNUTERuSDBTZFo1SUdYS0FZb0Zwai1UWGhSdm1TSWhOcjZ3NjgxQ0p0cTU3Zlc3WkRrZmlCZUt3cDZrS2xlbDNyZzZ3UDlzeHdsZG9VaUs4cE56MmQwbTN6RnRYX0tjWnEwLTJsTndvRHp5bHJDUWVpYi1XM1I0N3ZLdUFmd1hkRHYzM0Q4NnlfeFVsTjJIelNhdzUyVTZtYWhJc2lmNG5GdnpzVG5BV3FpcThjUWZqQUdCT2VhUG90cmVuSnZFZnJ3bVotWmJ4WFdKNUJ1M0tEVFkyWVNrTmkwRTN4b3draHl2b1o0QnY1clktckY5STlkVWVIcVpFcnVYRXU0WVl6SEI4MmVoWlFRdEpfbjJtYnZTNjBSUDFXV3VVd3lKUTZrRVVKSS05blFDZ0lJaGQ2STVYN2FlUkZXa19HZExQREg5U2VkSUhOZlREWG4wbDNMMTdPSzFlX0NBNHRtM2E2LUJUWFVrLUlhYkcxZkdGbjlsdlRGZVdXVF85NVJkS3VUUWlGZ0QtejNkUE9laFF2MFJPVk0wZ0VSZkRxckRZeTY0S09VZ3MwbXJ3MzNxNzJfaC16ZDJIQ2tYeVk3RV9DMUYtYThxbWVhYUpFVFBjVlMtVnhxZzA1SWludW9NOWxwM201Qk4waFR1QXgxT3owdFVVWTJuV0pRaWlxRjMxdHdWSk92RTJETjNmOFc4MlA2c3Z6eEU0ZFpWWDV0ZTJ3RWZSVkVubEJQMGIzc3Y5VjlmeUVqT0V2QzRFbmZES3hiZlROZEl6RmdWdTA3bVo3a21nOVRFSXZMSWxGd0RvdWpXYnB2M3RpWG1VaU5BM1B1dFdKSHZrLWdQNkh6dWxSbjJJY0JsdHdnYWZDV05qVWdLRlRmQ2dKZEdXZmR5SmhXTnZqaVFzbWxEcG5nbFNhLW5aMHVMeTF5Y2xUSmdkU2VtdTJ5ZC1fRHhrT2pjVHN2akpmVTM5b0hCdlBHNXJRWGtCZWVCcTNFUEJLaFUxcnVsRTZUYVdmMnZUcTVyVFVGUThBQjFTZGJVck54cGhIbk5HVmNiMzBGQzN3NkRzal9TSUI2VzZDS0RFQnpLclVCajZOX3o1a3FyMzAweXdJRktVSWY3b3ROMmhKS2dFbWNCUC1lOWlSZUdKbWRfakpFN0pqbnJLLUFUREdwZkFzNTBaOUo5eHRKMEhUSjMweTg4UzU5a2g1a2EtWHRkRzNMQ3h1dzItSUIzZVJ0aXFoaG51YV9lYzRRNkhHX1haS3U5d1ZBTVc3dXo0aHFoMlQxcGxBUWVHcndiVl9xWVUtRWdWM0l6RTZELVJ5ZWVpT01VRkxHaXJ2dFJpdWRVWE9TMnNlUndlc3FXU3JiNDllbGRuUFVZNUdkNlV3VmR1a1RfZzZ4WS1aQ21OcVFXZ01QSWxwcl92Tm1IVklvQWhXRWZRWHhiVWdRZ3VJNG0tYkFSREdfY2NQWUpnc01BUk9jZEVYaHI3VWxkNDdOQThFNnduMXZTSEJXMXZMWk5HbE50cERjY282UGVGMkRyRUpUdHFRbDJvTTFQZGFZZFVtVTFvdXVYM2tnLWlyTEI3Z2lvMjlrUnBGNDA1Vzhnc3NuRTNEeEVQVUtfU3ZyMW1ja3VlOFpvLVlQWkw4Y0ZXN29oQ3BTZkE5SHlSdUhTWEVYMkc5blJYOFF2Uk5xajdscWtvenAwWHhOTFRYQzNhMjJlR2tzMl9oM2NybkNlU3VoS191S0c5eEZUZnlZQUE3OVRlaUJ4Y0FFcGZLeUVkUjlKcWpzZ1NucmpmWkJKWV9NamRxbUlLRXZjMkgxUFlxQjlaaVJYSlpsbUZ4b2pzTGRaVlZNMW1JaGpnTFgxWC1Lel9ILUE1dzdyNEdpU0laLTlmczY5alYzVlJ2RTFWbDhZTUxNQlQ1QWVHOS1zMWVJcGpIbUZQQmpvWG1WaEIxWXBWd0JYWnU1c19vYU43VmhFLTV4REU2d2lESFk1YV9XR0FyclVkdGJocjNEMi1Ld0llR1p6STk4eFhEMGFuclgzc3E0UkxabFdseDBoYkg1bVFfa08wVS12V09aQThpWklTTUlYMGxWelRrWTJFYUFHWDhOT0tDRTVFSW05YTlLQzJTQV85UlpYNTFoS1F5SmpwWGh4ME9KR1hJZ1lOLWk1c3k2a1JiTkxheVBQSUcyRDZSemU2b0JxcF9oWm9VaHN6NjRoMkhlR2RDWWhPQ0pub1N0M3FwbkhTU1RRemN2d29MWE9WbVB6bldJdENMbFlITHVzaWRaNkpaT205b2R5M0ZQaHJnN05uLVFtanFLZlVpdmstVElnTWU0bTNpdE9KT1lqMllQYm1MZnVKLVYxOUM1R3lJNDVsMkVBUGlHZl9mU3FKVnE0dHhSNU1zT1dDM01OTmNxLVd3NE5Dem5HdzlpQmdXNER3VmFzby1Uek9pS2psMmF4bXdSV1VzRnMwNFRzVm9QWUVjWnQ2d2JJMmZDQXBlOGhZMU5wZ1kyS2praFFNaUxlY2VuazhZc3llcFc1c0RxOVJIWmF4bXZGNkt0cjFheW5yU1pLMnR2Mjk4eWE1ckc2RkxlVUp6UkxQT0FpRjB4Rl9YOWcxb1RqNHc0U0JuQlR6SHc4T1cyODRjY0Vqei1YVUo2UXVia016MmRwSFV4WDZPaE9YZnU1cDc0a1AwTmFhc0dhdzhBTmVOeS1rMlFGc3BvaHZLRVNxaHk1a01yRUlDY1ducG04UXBpQWYtY0Z4TVdWYkk2aUJ1My1WelhKU1QxbDNjMGtKRnR6Qnc0czVaWDB5c1FTa3FscEhQNzN0SEZCbDYzZUN4OV9yWUZGY1dMa3FHb2pEVDdaMU1xNG52OHVaQVhjTDdlNnluUlB3c3B0MlNYX1NTMUF0alVIVjc0ZG45RThMUXpGNXYzWFZadGFtdXA3OGhoWkkxcnlFUTVCUmt0TndhZ3lib1U2SmJuUzZNdy1QYXprcnRrRnVyeWRxQlVYUENZNS00NzYzZjFNM3cwYU50c0FudTA5cnR3UWZsMmlINlRyanZQTGwxVE1qVWNZZWRIS1c5eGVTN3RMNXAwQjV5RXM5ZTFva0VGZW8zbDJtUGxEYWJ5cm0tdVJxTU5mZm1QV3BUREZQRzBQN2VTdEhRZjJCQjVONWZSWjVTUU9uYkd5cksyVURUVllQVXNOLVdBclZxS2M3VmNfai1sTDVqUHIyWHVjejlWb2RNRjhsRkF0RGlOa2lxYU9VV2tXaElYV1hDdGVHYWVobU92ZmdVYWVDcktVTjhoRklxTjh1RllPT1BlVXJCUktGdXY0SDJGc0lGY2x5d09CNWtMSFRtQmpLRTRvVGNOc21zNDBUdEo0ZFpvUE9ObG9mOXFrbVRYaDRQemVFRnJyT2EwN2plWHYyOHJMV0o2Sm1nT25uVEZaaTJWUDM4VW5RSEd4dkJYRG9ZSmxuLWV6Z01ZU0Jfd2VNc2x4M3VHblAxeG1iQklRQjlYTDNUejJVa0RLOExZWDZrcC04b0ZtM29sLWlMS2pBNEtHdGlwTXlRRE84OGpKVk0xQzM1Z2JodkM3QUdpVk0wVFNqRy1GcGlDWm9QYzR5M2l4QlUwcXc3UWY1ekNJRjNuTUpzUE41Tjl1RW5KV25tUnc1NmNucTNBNUxlVFdNdHN0YnppMklLZXJoaGxLVTNRSWRTYWtqd3FpN1d3Nm5aMlFBUXlqNWpRYkxsd2R3OXZ3bW83ak5pcG9YZElFcjRjSlQtblpZSVJ6aFRHTU11aE5uMEVOUGpHRXFkRTFaZE9fRTl4UzBCblB1UkkxM0VDemdJT21RVTdxLVhUNG52aFBHSXhhWFhWXzdZZHJTc2R5d1JoSGJFMzNYbEUtaU5EOGQwRExEUlNkdFRESEJhVnhkajdxMVFReEQ5UlZUYWU3TWQ4dVh4b1pQSWJvUG1CS1MtR2xfb3JRN3RIUXdjcWtYZFU5STZudlRUbHhDM3JwMHpreXROWHRIaTlPUXduTHhuQlZGSlFJWVBJWXhlUzhjOUZRMXlONEgzMEFGUVh2T29GUkJuSkRCREFmWmpJaUt4bXppb2R1endGRjJLbzRFTlVKYUpMZjB1NWhGd1g0d1Nhd2ZXNldBWGVrQXNXdVpGTzBDa2pURHh3bzJMTFowZ3A2RFZKeHc0QXBJSmFYTXpYeThoa01QZHducjdLbVpzTDZiTThPVndJQXdFMnBSRXg1cjNHemFYLV9TbU5PT1VKWnBYakdHWE0tZ084Rnh0Q003RURSYjlKLUk0ckJXdGRyTUVrUnFsZjE0Sk01djNnb2pTR25UaU9RZGdzT0FNQU1nek9FQmxSX21LV1NWLWlvdlBOWWZQQXdWdjRBQzB4dTRacWFYRVh5eFFRdzdjSkNYbzdnZVNRdkVPeWM3bWhsVXppZzI5em1zcEZHZUd0dHpwMUl0cVNSU1lrTzAxY1BfMHNvWUZCT3AzbnZYc0duU25SUGR5N2Q5OVROMkhaOU1nMHh6S05fSFZuakNWN3NvcUc4YmNkQVUxc1dPbVJvUjR3UEJmQ3lHd2NFU081ZVVwa0pJLWFqTVl4VkV3dDhvY0wwSDB4MjNZN0JGWjI3cjk2RmF5OG9nZ2Q2cElUTTJFSExUdHJuOTlGdXdsaGphNWR2X25mTDRTa3F2OEgxcmRrVVp4elBrU3Y3ZXYzVXRQaDcydHBjeEZDX29jWkJHTGx0RnV4MWdHWUxSbHRQN1NUQUtIU1BraG9HWkFheUo2cDJKakFUMXhxY0g2dzZNZkpQa215TlJyVXJ5dUtoMWI0WGJYRmZKcXJaY2pTd3VZX1lISG9kWnJidlQ0RG4tMURpOE5yRTJpTkw1VDBkTXVkWV9FdVYyc2FUeG10ZWRvRy1CRzJxYmVRV3FyYlA1ejFULVJ6a1FHZXloOFV3enVaU29zV3BYTUNILUdWekhPMy1HUEIxdFVKcUtJT192SlJ6VUhGQlpYaG1mZk9sUHJfZVB3elRFYnMtNWRlQmhzNjVnZGlySnp4OHhSRldlVmxNSmhZYVdkUDNGZUFDZjhfQmtsR2J1b3JzREV1cU02V1JJWDlxUmhYajlHQ1lBd2VZcVJzV21fbFRnU2VyMERwTGQwWmtJdnRjN25iVHE0eVpOMnZCVE5POXJlMTdvcTBldXhzUzlkaFdEY3ByMVJKUS1ZX0RzVGlwaGE2cDIxaFBTMF92T0R1NWFyTVdXV19ieFlHSVpZaTRaU0NYZ1JhN1pPV0o1ZklHRV9FRFM3bFVjcGpZVUpBWjIzOTBNUmhjWENsaDNwTXBOQTREVzhrVnJ4OElNV2lYWlNPaDlKejNXV0c5MjM1UXNUUkhaVlpFNGFxSXhqSXMza0lPajlkeVlmX2RqRE85NHJpclJQY1RjWnZiOXBUX3k0OVZWYl91M0hkNDdLM3U4ZFJLUW9xcEg3VHJKM3B6WEw4cXFaSGVoQVQzQTg3blE5YTVtUFIxeElNYmx4SFBhaFFSQlBfZFJQZ0l1Z0d3QkhGWmdEczVXWnZFZ3pIZjUzdXJ3d3FKdmpCMjdpY0l2WWdDbDl1dUdpNVdrUUM4bjE1eTVUMzVHeFg1ajJVQl9ZYmhUdWhJYi1EWG9ObWxXWjQ5MVdpTkdPMzU5bC03LXFKLVlWSGxaOV9rSEVZc19WN0JZZWZpbWxneFByZnBJaVFCVEM4Y2xmNzlWTHNfOGF5Z3p4TGdRRENFQnBIWTNTV2Nualg2MWFtQzVkalNibXJOVTBQLUc0akE1TzBWdmlNZVg3RklPSHNJaWxqSE1ZbnBKLWpSb2ZWTmNGRUJNMmNfUWF4cnBKWjhLVW5IYnFidFVFdGhUd19HTE1leURTdEpjVFk5eHA3cGlXRDg1eVdWdk01T0VZSTVBcVdrOW9pTHZsV1VjZ0VXLWhjMU1DR3NlaU9COWFwMTZnU01tSjdXdHJSWDNrLUczdUs3MFUxSlA1S2FBLTZjcVRKYWhHWkN4Y0ZUSVNHVENYX2JLRms4VWF1U09SR1lUWnl6bFJhSHVHUk1hbjVjalpGcGpQeUREVGhVNXBKZmpBbnV6clpvWGxDalB1Uk5qcEdtakVfbkwweEZfdnY0WFMtVFJUcnBDNThpc0xobDlKRTJrQ1U2VzM4dmNwa2ZmNW90a2MzdHpGWUJpUFNxMkRmbUVZWHZaRzVEdS0zbVdHVzBYMUl1RThkbG5XUWNOeGVlU3A3aTFYQjFSd0x6X2hmMmtQVU81ZEFqR0hfbGhfaW1IUzZwSFpIbVR0X1Q4N0RsaUFFZHBPa2VmWWVESUdKV2dQR1lBT2VOZmVxbWQyakZhVWNnZVV6MEs1MFcwN2ZHajJwb2FzSE1RY0F4THJiZlhSWDJ0N1dIblZuYUEydHhtQzRuX2xNSjAzd3ZCbWVTc3NRRGI2MkRTYmhrUzZCVWtLUnpENUVEcVFSRHhXcVlQNXh0ZXNVdi1PRWRMcmdyMXFVM2FaUVplY2I0MW0xem83el9heGUwbGVXd1lWN1hyYWprMmp2c3ZFZmRGTEUxNmhTbGNTM3V1REJNeVZtelFiLS1RODVncnlIa09tMHpjc1hmVjNocmQzSC0zeEJfN3NkS0hlODBmeTFPRVp6WXJYMDBIeFF4Q202V1BzNXlMenJEeUJlUmlFTDR1Vml5eUZJTlhCTG1HelpkYnR3NEtRanBrcUpIRDdMbl9OMFZMWVRVRHNhSnBYcDZEWFlqeUJ4OWNBZXZSN21IaGV1djF5UG9nZEpCWTZiMDVZYWdSQndvTmg0NHFSaHJmclBxVFN2OHAzLXBCcjREUkl3S1NzS09RcVJyUVNFd1NGRFQ3Q2pkYWpINEtkcWdwUkhxcUdfOHladDRBblNOLUE0cDdmb0VWN2xvSXdRdHpKZnF2NlhjQUNfb0c1S1NzQkRYbFd6Tkt4WXY1UlQ0SC1jVzRheHpwek9WR0VEY3VlMmdzQS02R1dULTgtUW9lRHU2UWJrak1xamxCRHdBbFVNR2RTN2gtbUY3ZFhPdDFFeWdFU3FMTUQtamhveHFyQWxSVmQyMDkxV2R5VFRoY0o3QUZqRGlkMTVTMjJZRENOUEJXNFhkUjQtaDNtbHl1OEFMamVaRmtVUkhpU1B1cUE3eVlHVk1aYVppa0ZkZ3daZV95eEphR0MwbmtFSjQ1YzhKaU4tTW1NRlBHZnVMd0xKNlh5MWxEU19UX0d3V2NIVTVRX2VCSmFoMW01blhVVE0weGpCSzNuMlJocFVvOVF0ekx1UERLbzhsY1ZyZ2l3WWZkM2VGRkdPdWpxZnpsLTZCU3MyVmdDU0RPbnVybGNaeExXQ1BvNXhSVnlPVkx5ZGpSMlc5bWQ4b3JpcHAtQ1UtZDR6YS1faERscktmSWtIUi1GZG90MzVxNkFYXzNDMGQybTUyTXdmRmhSd25sNVBZc2h0VGNNUDY2MTdoUDJhQk8zOU13OWJjVGYtaldaUWFuRnZkWHBZOHdGaUsxMi1YdHNQN2RiMThoNlkzVW9vbGhPTGF5YnA4OXpLQXpuSzRlcXNxc3Z4Sl9ITVNSVVZ4cHBtZmx0MV9NUHdhNWhQeHVTMm94SVNYaTQtTlV0WXVWVlhhVS1BcGVUV05XTTE2VW5KYlNwSmtaODUyT0lBdDVGNXJKSkxvTXVONG9Yc202RnRuTUJBbXhXUDdvNGJYdzhSVTNDNkREamx3VnlJdjlLdzh2YXlkdHZFendUNkNWQUVyOFA4REJNRzZ4SFBZYkQ5VmZfZ3RhY3M0dVhFMWI1My1hb2UxMVU5WDczYm1VbHdWX3Z1dUJXM3dJSzl2ZW00Z2s0MUtJN2QzSHV2UWxJODIxbzdXMTNScS11LUQxenBVRlNaYmg1dS1iU2g5M2VJMFI1ejZLYW9GYlZZZmgweXdzTXdxbXFtWV9XSVdrWGFncGVCN08wZzkwSjdKUGQyZjhFbk1ncVUwUmpUNXM3U2xsLWdKSF9PTkRRRDdRSUhJM2VFcmJraEN4X0hDQ1RsSUs1cXZzZjZCemNUSVU4SE1mTU0wN2phQlFEX1ZOaGpIdFpKRHdJNmxtZHVoSHdTbC1vaUlsdkJ0eHlNNkdmOEhLSmZicmk5VVZPdDdVUXZkdDZsQU5EOGdfQlZWQl9ic2VDZlFlOUVNck1QckVkMXBTX0NSOHE3aXVjMlpuTjNEalRkemxwdGstOWl3RTY3SlRVdkNnSXNZZDA3VG9vVGdGc1F5c3lBem1BU2hfNnFQcHoyZ1hrdFR0SThIZ3N2dm5Yc0ozb0ZjV2JSellIVnRiM2pwT1lsckQxekw3M2FZbTNGLWFlME1aN3FzWFV2WUZwTkZNWC1EYnRaMHREU3J5ME1KQkFUelEyd1lUdExKemtNUnFac1VaU0ZYYXJvWVBOam4xT1BzRnM9"
//           }]
//}

type Empty struct {
	Type      TransactionType `json:"type"`
	Version   byte            `json:"version,omitempty"`
	ID        string          `json:"sender,omitempty"`
	Timestamp uint64          `json:"timestamp,omitempty"`
	Fee       int64           `json:"fee"`
	Sender    string          `json:"sender,omitempty"`
}

func (Empty) Transaction() {}
func (tx Empty) GetID() []byte {
	return []byte(tx.ID)
}
