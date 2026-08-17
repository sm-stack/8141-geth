// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/filtermaps"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

// TestSetFeeDefaults tests the logic for filling in default fee values works as expected.
func TestSetFeeDefaults(t *testing.T) {
	t.Parallel()

	type test struct {
		name string
		fork string // options: legacy, london, cancun
		in   *TransactionArgs
		want *TransactionArgs
		err  error
	}

	var (
		b        = newBackendMock()
		zero     = (*hexutil.Big)(big.NewInt(0))
		fortytwo = (*hexutil.Big)(big.NewInt(42))
		maxFee   = (*hexutil.Big)(new(big.Int).Add(new(big.Int).Mul(b.current.BaseFee, big.NewInt(2)), fortytwo.ToInt()))
		al       = &types.AccessList{types.AccessTuple{Address: common.Address{0xaa}, StorageKeys: []common.Hash{{0x01}}}}
		authList = []types.SetCodeAuthorization{{Address: common.Address{0xbb}}}
	)

	tests := []test{
		// Legacy txs
		{
			"legacy tx pre-London",
			"legacy",
			&TransactionArgs{},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"legacy tx pre-London with zero price",
			"legacy",
			&TransactionArgs{GasPrice: zero},
			&TransactionArgs{GasPrice: zero},
			nil,
		},
		{
			"legacy tx post-London, explicit gas price",
			"london",
			&TransactionArgs{GasPrice: fortytwo},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"legacy tx post-London with zero price",
			"london",
			&TransactionArgs{GasPrice: zero},
			nil,
			errors.New("gasPrice must be non-zero after london fork"),
		},

		// Access list txs
		{
			"access list tx pre-London",
			"legacy",
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx post-London, explicit gas price",
			"legacy",
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx post-London",
			"london",
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"access list tx post-London, only max fee",
			"london",
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"access list tx post-London, only priority fee",
			"london",
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},

		// Dynamic fee txs
		{
			"dynamic tx post-London",
			"london",
			&TransactionArgs{},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic tx post-London, only max fee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic tx post-London, only priority fee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic fee tx pre-London, maxFee set",
			"legacy",
			&TransactionArgs{MaxFeePerGas: maxFee},
			nil,
			errors.New("maxFeePerGas and maxPriorityFeePerGas are not valid before London is active"),
		},
		{
			"dynamic fee tx pre-London, priorityFee set",
			"legacy",
			&TransactionArgs{MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("maxFeePerGas and maxPriorityFeePerGas are not valid before London is active"),
		},
		{
			"dynamic fee tx, maxFee < priorityFee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1000))},
			nil,
			errors.New("maxFeePerGas (0x3e) < maxPriorityFeePerGas (0x3e8)"),
		},
		{
			"dynamic fee tx, maxFee < priorityFee while setting default",
			"london",
			&TransactionArgs{MaxFeePerGas: (*hexutil.Big)(big.NewInt(7))},
			nil,
			errors.New("maxFeePerGas (0x7) < maxPriorityFeePerGas (0x2a)"),
		},
		{
			"dynamic fee tx post-London, explicit gas price",
			"london",
			&TransactionArgs{MaxFeePerGas: zero, MaxPriorityFeePerGas: zero},
			nil,
			errors.New("maxFeePerGas must be non-zero"),
		},

		// Misc
		{
			"set all fee parameters",
			"legacy",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and maxPriorityFee",
			"legacy",
			&TransactionArgs{GasPrice: fortytwo, MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and maxFee",
			"london",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and authorization list",
			"london",
			&TransactionArgs{GasPrice: fortytwo, AuthorizationList: authList},
			nil,
			errors.New("both gasPrice and authorizationList specified"),
		},
		// EIP-4844
		{
			"set gas price and maxFee for blob transaction",
			"cancun",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee, BlobHashes: []common.Hash{}},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"fill maxFeePerBlobGas",
			"cancun",
			&TransactionArgs{BlobHashes: []common.Hash{}},
			&TransactionArgs{BlobHashes: []common.Hash{}, BlobFeeCap: (*hexutil.Big)(big.NewInt(4)), MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"fill maxFeePerBlobGas when dynamic fees are set",
			"cancun",
			&TransactionArgs{BlobHashes: []common.Hash{}, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			&TransactionArgs{BlobHashes: []common.Hash{}, BlobFeeCap: (*hexutil.Big)(big.NewInt(4)), MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
	}

	ctx := context.Background()
	for i, test := range tests {
		if err := b.setFork(test.fork); err != nil {
			t.Fatalf("failed to set fork: %v", err)
		}
		got := test.in
		err := got.setFeeDefaults(ctx, b, b.CurrentHeader())
		if err != nil {
			if test.err == nil {
				t.Fatalf("test %d (%s): unexpected error: %s", i, test.name, err)
			} else if err.Error() != test.err.Error() {
				t.Fatalf("test %d (%s): unexpected error: (got: %s, want: %s)", i, test.name, err, test.err)
			}
			// Matching error.
			continue
		} else if test.err != nil {
			t.Fatalf("test %d (%s): expected error: %s", i, test.name, test.err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("test %d (%s): did not fill defaults as expected: (got: %v, want: %v)", i, test.name, got, test.want)
		}
	}
}

func TestTransactionArgsFrameTxJSONToTransaction(t *testing.T) {
	t.Parallel()

	signature := "0x" + strings.Repeat("11", 65)
	input := fmt.Sprintf(`{
		"from":"0x0000000000000000000000000000000000001111",
		"sender":"0x000000000000000000000000000000000000abcd",
		"nonce":"0x3",
		"chainId":"0x2a",
		"maxFeePerGas":"0x64",
		"maxPriorityFeePerGas":"0x2",
		"maxFeePerBlobGas":"0x0",
		"frames":[
			{"mode":"0x1","flags":"0x3","target":null,"gasLimit":"0xc350","value":"0x0","data":"0x736967"},
			{"mode":"0x2","flags":"0x0","target":"0x0000000000000000000000000000000000001234","gasLimit":"0x13880","value":"0x7b","data":"0x63616c6c"}
		],
		"signatures":[{"scheme":"0x1","signer":"0x000000000000000000000000000000000000abcd","msg":"0x","signature":"%s"}]
	}`, signature)

	var args TransactionArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unmarshal frame tx args: %v", err)
	}
	tx := args.ToTransaction(types.FrameTxType)
	if tx.Type() != types.FrameTxType {
		t.Fatalf("type mismatch: got %d want %d", tx.Type(), types.FrameTxType)
	}
	ftx := tx.GetFrameTx()
	if ftx == nil {
		t.Fatal("missing frame tx payload")
	}
	if err := ftx.Validate(); err != nil {
		t.Fatalf("frame tx args produced invalid transaction: %v", err)
	}
	if want := common.HexToAddress("0xabcd"); ftx.Sender != want {
		t.Fatalf("sender mismatch: got %s want %s", ftx.Sender, want)
	}
	if len(ftx.Frames) != 2 {
		t.Fatalf("frames length mismatch: got %d want 2", len(ftx.Frames))
	}
	if ftx.Frames[0].Flags != 3 || ftx.Frames[1].Value == nil || ftx.Frames[1].Value.Uint64() != 123 {
		t.Fatalf("unexpected frame args: %#v", ftx.Frames)
	}
	if len(ftx.Signatures) != 1 || len(ftx.Signatures[0].Signature) != 65 {
		t.Fatalf("unexpected signatures: %#v", ftx.Signatures)
	}
	if ftx.NonceSeq != 3 || len(ftx.NonceKeys) != 1 || !ftx.NonceKeys[0].IsZero() {
		t.Fatalf("unexpected nonce: keys=%v seq=%d", ftx.NonceKeys, ftx.NonceSeq)
	}
	if len(ftx.RecentRootRefs) != 0 {
		t.Fatalf("unexpected recent root references: %#v", ftx.RecentRootRefs)
	}
}

func TestTransactionArgsFrameTxLegacyNonceAlias(t *testing.T) {
	nonce := hexutil.Uint64(7)
	chainID := (*hexutil.Big)(big.NewInt(42))
	frames := []types.Frame{{Mode: types.FrameModeDefault, GasLimit: 1, Value: new(uint256.Int)}}
	args := &TransactionArgs{
		Nonce: &nonce, ChainID: chainID, Frames: &frames,
		MaxFeePerGas: (*hexutil.Big)(big.NewInt(1)), MaxPriorityFeePerGas: new(hexutil.Big), BlobFeeCap: new(hexutil.Big),
	}
	ftx := args.ToTransaction(types.FrameTxType).GetFrameTx()
	if !ftx.UsesLegacyNonce() || ftx.NonceSeq != 7 {
		t.Fatalf("legacy nonce alias produced keys=%v seq=%d", ftx.NonceKeys, ftx.NonceSeq)
	}
}

func TestCallDefaultsRejectsFrameNonceKeysWithoutSequence(t *testing.T) {
	frames := []types.Frame{}
	args := &TransactionArgs{
		Frames:    &frames,
		NonceKeys: []*hexutil.Big{(*hexutil.Big)(big.NewInt(1))},
	}
	if err := args.CallDefaults(1_000_000, big.NewInt(1), big.NewInt(42)); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("CallDefaults error = %v, want obsolete nonce field rejection", err)
	}
}

func TestSetFeeDefaultsRejectsFrameTxGasPrice(t *testing.T) {
	t.Parallel()

	b := newBackendMock()
	if err := b.setFork("london"); err != nil {
		t.Fatalf("failed to set fork: %v", err)
	}
	frames := []types.Frame{}
	args := &TransactionArgs{
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		Frames:   &frames,
	}
	err := args.setFeeDefaults(context.Background(), b, b.CurrentHeader())
	if err == nil || err.Error() != "gasPrice is not supported for frame transactions" {
		t.Fatalf("unexpected error: got %v", err)
	}
}

type backendMock struct {
	current *types.Header
	config  *params.ChainConfig
}

func newBackendMock() *backendMock {
	var cancunTime uint64 = 600
	config := &params.ChainConfig{
		ChainID:             big.NewInt(42),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(1000),
		CancunTime:          &cancunTime,
		BlobScheduleConfig:  params.DefaultBlobSchedule,
	}
	return &backendMock{
		current: &types.Header{
			Difficulty: big.NewInt(10000000000),
			Number:     big.NewInt(1100),
			GasLimit:   8_000_000,
			GasUsed:    8_000_000,
			Time:       555,
			Extra:      make([]byte, 32),
			BaseFee:    big.NewInt(10),
		},
		config: config,
	}
}

func (b *backendMock) setFork(fork string) error {
	if fork == "legacy" {
		b.current.Number = big.NewInt(900)
		b.current.Time = 555
	} else if fork == "london" {
		b.current.Number = big.NewInt(1100)
		b.current.Time = 555
	} else if fork == "cancun" {
		b.current.Number = big.NewInt(1100)
		b.current.Time = 700
		// Blob base fee will be 2
		excess := uint64(2314058)
		b.current.ExcessBlobGas = &excess
	} else {
		return errors.New("invalid fork")
	}
	return nil
}

func (b *backendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(42), nil
}
func (b *backendMock) BlobBaseFee(ctx context.Context) *big.Int { return big.NewInt(42) }
func (b *backendMock) BaseFee(ctx context.Context) *big.Int     { return big.NewInt(42) }

func (b *backendMock) CurrentHeader() *types.Header     { return b.current }
func (b *backendMock) ChainConfig() *params.ChainConfig { return b.config }

// Other methods needed to implement Backend interface.
func (b *backendMock) SyncProgress(ctx context.Context) ethereum.SyncProgress {
	return ethereum.SyncProgress{}
}
func (b *backendMock) FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, []*big.Int, []float64, error) {
	return nil, nil, nil, nil, nil, nil, nil
}
func (b *backendMock) ChainDb() ethdb.Database           { return nil }
func (b *backendMock) AccountManager() *accounts.Manager { return nil }
func (b *backendMock) ExtRPCEnabled() bool               { return false }
func (b *backendMock) RPCGasCap() uint64                 { return 0 }
func (b *backendMock) RPCEVMTimeout() time.Duration      { return time.Second }
func (b *backendMock) RPCTxFeeCap() float64              { return 0 }
func (b *backendMock) UnprotectedAllowed() bool          { return false }
func (b *backendMock) SetHead(number uint64) error       { return nil }
func (b *backendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) CurrentBlock() *types.Header { return nil }
func (b *backendMock) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error) {
	return nil, nil
}
func (b *backendMock) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) Pending() (*types.Block, types.Receipts, *state.StateDB) { return nil, nil, nil }
func (b *backendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return nil, nil
}
func (b *backendMock) GetCanonicalReceipt(tx *types.Transaction, blockHash common.Hash, blockNumber, blockIndex uint64) (*types.Receipt, error) {
	return nil, nil
}
func (b *backendMock) GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error) {
	return nil, nil
}
func (b *backendMock) GetEVM(ctx context.Context, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockCtx *vm.BlockContext) *vm.EVM {
	return nil
}
func (b *backendMock) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription { return nil }
func (b *backendMock) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return nil
}
func (b *backendMock) SendTx(ctx context.Context, signedTx *types.Transaction) error { return nil }
func (b *backendMock) GetCanonicalTransaction(txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64) {
	return false, nil, [32]byte{}, 0, 0
}
func (b *backendMock) TxIndexDone() bool                                        { return true }
func (b *backendMock) GetPoolTransactions() (types.Transactions, error)         { return nil, nil }
func (b *backendMock) GetPoolTransaction(txHash common.Hash) *types.Transaction { return nil }
func (b *backendMock) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return 0, nil
}
func (b *backendMock) Stats() (pending int, queued int) { return 0, 0 }
func (b *backendMock) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}
func (b *backendMock) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}
func (b *backendMock) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription { return nil }
func (b *backendMock) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription    { return nil }
func (b *backendMock) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return nil
}

func (b *backendMock) Engine() consensus.Engine { return nil }

func (b *backendMock) CurrentView() *filtermaps.ChainView           { return nil }
func (b *backendMock) NewMatcherBackend() filtermaps.MatcherBackend { return nil }

func (b *backendMock) HistoryPruningCutoff() uint64       { return 0 }
func (b *backendMock) HistoryRetention() HistoryRetention { return HistoryRetention{} }
