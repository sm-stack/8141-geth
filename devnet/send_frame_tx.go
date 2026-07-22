// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Standalone tool to send an EIP-8141 frame transaction to a geth dev node.
// Usage:
//   1. Start the dev node: bash devnet/run.sh
//   2. Run this tool:      go run ./devnet/send_frame_tx.go

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
)

const (
	rpcURL  = "http://localhost:18545"
	chainID = 1337

	// Well-known geth --dev account private key.
	devKeyHex = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
)

// SimpleAccount init bytecode from contracts/out/SimpleAccount.sol/SimpleAccount.json.
// Constructor takes a single argument: address _owner.
var simpleAccountInitCode = mustDecodeHex(
	"608060405234801561000f575f5ffd5b50604051610821380380610821833981810160405281019061003191906100d4565b805f5f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506100ff565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100a38261007a565b9050919050565b6100b381610099565b81146100bd575f5ffd5b50565b5f815190506100ce816100aa565b92915050565b5f602082840312156100e9576100e8610076565b5b5f6100f6848285016100c0565b91505092915050565b6107158061010c5f395ff3fe608060405260043610610037575f3560e01c80638da5cb5b14610042578063b61d27f61461006c578063f2d64fed146100945761003e565b3661003e57005b5f5ffd5b34801561004d575f5ffd5b506100566100bc565b60405161006391906103e3565b60405180910390f35b348015610077575f5ffd5b50610092600480360381019061008d91906104c2565b6100e0565b005b34801561009f575f5ffd5b506100ba60048036038101906100b5919061059c565b6101ef565b005b5f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b3073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610145576040517f48f5c3ed00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8473ffffffffffffffffffffffffffffffffffffffff1684848460405161016e92919061063c565b5f6040518083038185875af1925050503d805f81146101a8576040519150601f19603f3d011682016040523d82523d5f602084013e6101ad565b606091505b50509050806101e8576040517facfdb44400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5050505050565b60aa73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610255576040517f48f5c3ed00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f61025e61037d565b90505f6001828787876040515f81526020016040526040516102839493929190610672565b6020604051602081039080840390855afa1580156102a3573d5f5f3e3d5ffd5b5050506020604051035190505f5f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614158061033557505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16145b1561036c576040517f8baa579f00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6103758361038f565b505050505050565b5f61038a60085f5f610396565b905090565b805f5faa50565b5f818385b090509392505050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6103cd826103a4565b9050919050565b6103dd816103c3565b82525050565b5f6020820190506103f65f8301846103d4565b92915050565b5f5ffd5b5f5ffd5b61040d816103c3565b8114610417575f5ffd5b50565b5f8135905061042881610404565b92915050565b5f819050919050565b6104408161042e565b811461044a575f5ffd5b50565b5f8135905061045b81610437565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f84011261048257610481610461565b5b8235905067ffffffffffffffff81111561049f5761049e610465565b5b6020830191508360018202830111156104bb576104ba610469565b5b9250929050565b5f5f5f5f606085870312156104da576104d96103fc565b5b5f6104e78782880161041a565b94505060206104f88782880161044d565b935050604085013567ffffffffffffffff81111561051957610518610400565b5b6105258782880161046d565b925092505092959194509250565b5f60ff82169050919050565b61054881610533565b8114610552575f5ffd5b50565b5f813590506105638161053f565b92915050565b5f819050919050565b61057b81610569565b8114610585575f5ffd5b50565b5f8135905061059681610572565b92915050565b5f5f5f5f608085870312156105b4576105b36103fc565b5b5f6105c187828801610555565b94505060206105d287828801610588565b93505060406105e387828801610588565b92505060606105f487828801610555565b91505092959194509250565b5f81905092915050565b828183375f83830152505050565b5f6106238385610600565b935061063083858461060a565b82840190509392505050565b5f610648828486610618565b91508190509392505050565b61065d81610569565b82525050565b61066c81610533565b82525050565b5f6080820190506106855f830187610654565b6106926020830186610663565b61069f6040830185610654565b6106ac6060830184610654565b9594505050505056fea26469706673582212206577161935da229b8e3952534c6731fc61d1d5062d328678ccfd685cbedadb4764736f6c63782c302e382e33332d646576656c6f702e323032362e322e31322b636f6d6d69742e36343131386632312e6d6f64005d",
)

// validate(uint8,bytes32,bytes32,uint8) selector = 0xf2d64fed
var validateSelector = mustDecodeHex("f2d64fed")

func main() {
	ctx := context.Background()

	// 1. Parse keys.
	devKey := mustParseKey(devKeyHex)
	devAddr := crypto.PubkeyToAddress(devKey.PublicKey)
	// Use dev key as owner for simplicity.
	ownerKey := devKey
	ownerAddr := crypto.PubkeyToAddress(ownerKey.PublicKey)

	// 2. Connect to dev node.
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		fatal("failed to connect to dev node: %v", err)
	}
	defer client.Close()

	// 3. Verify connection.
	balance, err := client.BalanceAt(ctx, devAddr, nil)
	if err != nil {
		fatal("failed to get balance: %v", err)
	}
	fmt.Printf("Dev account %s balance: %s wei\n", devAddr.Hex(), balance.String())

	// 4. Deploy SimpleAccount(ownerAddr).
	deployNonce, err := client.PendingNonceAt(ctx, devAddr)
	if err != nil {
		fatal("failed to get nonce: %v", err)
	}
	simpleAccountAddr := crypto.CreateAddress(devAddr, deployNonce)
	fmt.Printf("Expected SimpleAccount address: %s\n", simpleAccountAddr.Hex())

	deployHash, err := deploySimpleAccount(ctx, client, devKey, ownerAddr)
	if err != nil {
		fatal("failed to deploy SimpleAccount: %v", err)
	}
	fmt.Printf("Deploy tx: %s\n", deployHash.Hex())

	// 5. Wait for deploy receipt.
	deployReceipt, err := waitForReceipt(ctx, client, deployHash, 30*time.Second)
	if err != nil {
		fatal("deploy receipt: %v", err)
	}
	if deployReceipt.Status != types.ReceiptStatusSuccessful {
		fatal("deploy failed: status=%d", deployReceipt.Status)
	}
	fmt.Printf("Deploy receipt: status=%d, contract=%s\n",
		deployReceipt.Status, deployReceipt.ContractAddress.Hex())

	// 6. Fund SimpleAccount with 10 ETH.
	fundHash, err := fundAccount(ctx, client, devKey, simpleAccountAddr, toWei(10))
	if err != nil {
		fatal("failed to fund SimpleAccount: %v", err)
	}
	fundReceipt, err := waitForReceipt(ctx, client, fundHash, 30*time.Second)
	if err != nil {
		fatal("fund receipt: %v", err)
	}
	fmt.Printf("Fund receipt: status=%d\n", fundReceipt.Status)

	// 7. Build FrameTx.
	frameTx, err := buildFrameTx(ctx, client, ownerKey, simpleAccountAddr)
	if err != nil {
		fatal("failed to build FrameTx: %v", err)
	}
	fmt.Printf("FrameTx hash: %s\n", frameTx.Hash().Hex())

	// 8. Send FrameTx.
	if err := client.SendTransaction(ctx, frameTx); err != nil {
		fatal("failed to send FrameTx: %v", err)
	}
	fmt.Println("FrameTx sent")

	// 9. Wait for receipt and verify.
	frameReceipt, err := waitForReceipt(ctx, client, frameTx.Hash(), 30*time.Second)
	if err != nil {
		fatal("frame receipt: %v", err)
	}
	printReceipt(frameReceipt)

	if err := verifyReceipt(frameReceipt, simpleAccountAddr); err != nil {
		fatal("receipt verification failed: %v", err)
	}

	fmt.Println("\n=== E2E TEST PASSED ===")
}

// deploySimpleAccount deploys SimpleAccount(ownerAddr) via a CREATE tx.
func deploySimpleAccount(ctx context.Context, client *ethclient.Client, devKey *ecdsa.PrivateKey, ownerAddr common.Address) (common.Hash, error) {
	devAddr := crypto.PubkeyToAddress(devKey.PublicKey)
	nonce, err := client.PendingNonceAt(ctx, devAddr)
	if err != nil {
		return common.Hash{}, err
	}

	// Append ABI-encoded constructor argument: address _owner (32 bytes).
	constructorArg := common.LeftPadBytes(ownerAddr.Bytes(), 32)
	deployData := make([]byte, len(simpleAccountInitCode)+len(constructorArg))
	copy(deployData, simpleAccountInitCode)
	copy(deployData[len(simpleAccountInitCode):], constructorArg)

	signer := types.LatestSignerForChainID(big.NewInt(chainID))
	tx, err := types.SignNewTx(devKey, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),  // 1 gwei
		GasFeeCap: big.NewInt(10_000_000_000), // 10 gwei
		Gas:       2_000_000,
		To:        nil, // contract creation
		Value:     big.NewInt(0),
		Data:      deployData,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), client.SendTransaction(ctx, tx)
}

// fundAccount sends ETH from the dev account to the target address.
func fundAccount(ctx context.Context, client *ethclient.Client, devKey *ecdsa.PrivateKey, target common.Address, amount *big.Int) (common.Hash, error) {
	devAddr := crypto.PubkeyToAddress(devKey.PublicKey)
	nonce, err := client.PendingNonceAt(ctx, devAddr)
	if err != nil {
		return common.Hash{}, err
	}

	signer := types.LatestSignerForChainID(big.NewInt(chainID))
	tx, err := types.SignNewTx(devKey, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(10_000_000_000),
		Gas:       50_000, // > 21000 to cover contract receive() execution
		To:        &target,
		Value:     amount,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return tx.Hash(), client.SendTransaction(ctx, tx)
}

// buildFrameTx constructs an EIP-8141 frame transaction.
//
// Example 1 — Simple Transaction:
//
//	Frame 0: VERIFY(sender)  -> validate(v, r, s, scope=2) -> APPROVE(both)
//	Frame 1: SENDER(target)  -> simple call (empty data)
func buildFrameTx(ctx context.Context, client *ethclient.Client, ownerKey *ecdsa.PrivateKey, simpleAccountAddr common.Address) (*types.Transaction, error) {
	// Get SimpleAccount nonce (should be 1 after contract creation per EIP-161).
	accountNonce, err := client.NonceAt(ctx, simpleAccountAddr, nil)
	if err != nil {
		return nil, fmt.Errorf("get account nonce: %w", err)
	}
	fmt.Printf("SimpleAccount nonce: %d\n", accountNonce)

	// Get current base fee.
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get header: %w", err)
	}
	baseFee := header.BaseFee
	// Set gasFeeCap = baseFee + 2 gwei (generous margin).
	gasFeeCap := new(big.Int).Add(baseFee, big.NewInt(2_000_000_000))
	fmt.Printf("BaseFee: %s, GasFeeCap: %s\n", baseFee.String(), gasFeeCap.String())

	// Target address for the SENDER frame (just a simple call to a burn address).
	targetAddr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	verifyGas := uint64(200_000)
	senderGas := uint64(50_000)

	// Build FrameTx with placeholder VERIFY data.
	// sigHash elides VERIFY data, so placeholder doesn't affect the hash.
	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(chainID),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  accountNonce,
		Sender:    simpleAccountAddr,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: verifyGas, Data: nil},
			{Mode: types.FrameModeSender, Target: &targetAddr, GasLimit: senderGas, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1_000_000_000),
		GasFeeCap:  uint256.MustFromBig(gasFeeCap),
		BlobFeeCap: uint256.NewInt(0),
		BlobHashes: []common.Hash{},
	}

	// Compute sigHash (VERIFY data is elided, so value is stable).
	sigHash := ftx.SigHash(big.NewInt(chainID))
	fmt.Printf("SigHash: %s\n", sigHash.Hex())

	// Sign sigHash with owner's private key.
	sig, err := crypto.Sign(sigHash[:], ownerKey)
	if err != nil {
		return nil, fmt.Errorf("sign sig hash: %w", err)
	}
	// crypto.Sign returns [R(32) | S(32) | V(1)] where V is 0 or 1.
	// Solidity ecrecover expects V = 27 or 28.
	v := sig[64] + 27
	r := sig[0:32]
	s := sig[32:64]

	// ABI-encode validate(uint8 v, bytes32 r, bytes32 s, uint8 scope).
	// Selector: f2d64fed
	calldata := make([]byte, 4+32*4) // 132 bytes
	copy(calldata[0:4], validateSelector)
	calldata[35] = v                                   // uint8 v in last byte of word 1
	copy(calldata[36:68], common.LeftPadBytes(r, 32))  // bytes32 r
	copy(calldata[68:100], common.LeftPadBytes(s, 32)) // bytes32 s
	calldata[131] = 2                                  // uint8 scope=2 (both) in last byte of word 4

	// Set the VERIFY frame data.
	ftx.Frames[0].Data = calldata

	return types.NewTx(ftx), nil
}

// waitForReceipt polls for a transaction receipt until timeout.
func waitForReceipt(ctx context.Context, client *ethclient.Client, txHash common.Hash, timeout time.Duration) (*types.Receipt, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			return receipt, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for receipt of tx %s", txHash.Hex())
}

// verifyReceipt checks the frame transaction receipt fields.
func verifyReceipt(receipt *types.Receipt, simpleAccountAddr common.Address) error {
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("status: got %d, want %d (successful)", receipt.Status, types.ReceiptStatusSuccessful)
	}
	if receipt.Type != types.FrameTxType {
		return fmt.Errorf("type: got %d, want %d (FrameTx)", receipt.Type, types.FrameTxType)
	}
	if receipt.Payer != simpleAccountAddr {
		return fmt.Errorf("payer: got %s, want %s", receipt.Payer.Hex(), simpleAccountAddr.Hex())
	}
	if len(receipt.FrameReceipts) != 2 {
		return fmt.Errorf("frame receipts count: got %d, want 2", len(receipt.FrameReceipts))
	}
	// Frame 0 (VERIFY): should be ApproveBoth (status=4).
	if receipt.FrameReceipts[0].Status != 4 {
		return fmt.Errorf("frame 0 status: got %d, want 4 (ApproveBoth)", receipt.FrameReceipts[0].Status)
	}
	// Frame 1 (SENDER): should be success (status=1).
	if receipt.FrameReceipts[1].Status != 1 {
		return fmt.Errorf("frame 1 status: got %d, want 1 (success)", receipt.FrameReceipts[1].Status)
	}
	if receipt.GasUsed == 0 {
		return fmt.Errorf("gas used should be > 0")
	}
	return nil
}

func printReceipt(r *types.Receipt) {
	fmt.Printf("\n--- Frame Transaction Receipt ---\n")
	fmt.Printf("Status:   %d\n", r.Status)
	fmt.Printf("Type:     %d (FrameTx=6)\n", r.Type)
	fmt.Printf("GasUsed:  %d\n", r.GasUsed)
	fmt.Printf("Payer:    %s\n", r.Payer.Hex())
	for i, fr := range r.FrameReceipts {
		statusName := "unknown"
		switch fr.Status {
		case 0:
			statusName = "Failed"
		case 1:
			statusName = "Success"
		case 2:
			statusName = "ApproveExecution"
		case 3:
			statusName = "ApprovePayment"
		case 4:
			statusName = "ApproveBoth"
		}
		fmt.Printf("Frame %d:  status=%d (%s), gasUsed=%d\n", i, fr.Status, statusName, fr.GasUsed)
	}
}

// --- Helpers ---

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex: %v", err))
	}
	return b
}

func mustParseKey(hexKey string) *ecdsa.PrivateKey {
	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		panic(fmt.Sprintf("invalid key: %v", err))
	}
	return key
}

func toWei(eth int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(eth), big.NewInt(1e18))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}
