# EIP-8141 validation split transition

This package contains a current-format proof of concept for bounding validation
work that can change after a head update. It does not change the transaction or
frame wire format.

## Policy and accounting

Every EVM validation frame records the gas remaining immediately before its
first mutable read. This is a frame-wide remaining budget, including gas
retained by active parent calls, rather than the gas eventually consumed by the
observed suffix. Before the transaction-global watershed, a frame with no
mutable read contributes zero. A deploy validation frame contributes its full
declared execution gas. Once any frame observes mutable input, every later
validation frame contributes its full
declared execution gas because prior-frame results, gas-used fields, and the
shared warm-access journal can carry that influence across frame boundaries.
Signature gas is still included in `MaxVerifyGas`, but not in the
state-dependent sum.

The current mutable sources are sender or profiling-only `SLOAD`, the legacy
nonce selector of `TXPARAM`, blob transactions' blob-base-fee-dependent
`TXPARAM(max_cost)`, external code identity (including `EXTCODE*` at a
precompile address), the canonical expiry verifier's `TIMESTAMP`, deployment,
and prior-frame mutable influence. Unsupported environment and balance opcodes
remain rejected by the existing public-pool rules. Calling an active precompile
is a fork-scoped pure function and is not a code watershed.

Gas accounting fails closed to the full frame gas limit on depth mismatch,
underflow, overflow, or an impossible remaining-gas total. The pool applies
`MaxStateDependentVerifyGas` only after the complete validation prefix succeeds.
This blocks a cheap admission branch from hiding expensive work behind a state
read because the policy charges the budget remaining at that read.

The top-level sender, payer, delegation implementation, deploy factory, and
traced external libraries form the validation program fingerprint together
with fork rules. A changed fingerprint is dropped before signature checking or
VERIFY execution. Stable program identity is what makes the transaction-global
admission watershed invariant when only storage values change. Profiles after
that watershed are diagnostic and are not required to remain identical.

FramePool simulation initializes `FrameResults` and `FrameGasUsed`, records
each completed validation frame before executing the next, and shares one
transaction access journal. This matches block execution for validators that
inspect prior-frame runtime fields or rely on warm/cold access accounting.

Recent-root opcodes read immutable references encoded in the transaction. The
referenced canonical entry is still mutable, but FramePool checks mismatch,
expiry, and reorg directly before it queues expensive validation. That ordering
is required for recent-root reads to stay outside the EVM watershed.

## Transaction-local precompile memo

`CacheValidationPrecompiles` attaches one strict-bounded memo to all validation
frames of an admitted transaction and retains it across reset validation. No
entry is shared between transactions. Keys contain the active precompile set,
address, and normalized exact input bytes; outputs are copied on storage and
return. Gas charging and state touching happen before lookup, so a hit skips
only CPU recomputation.

The memo never evicts. Deterministic precompile failures are cached with their
failure outcome. An uncacheable call or a capacity miss marks it incomplete
while execution continues normally. Statistics and completeness distinguish
calls before and after the transaction-global watershed; an after-watershed hit
is a safe exact-input optimization, not evidence of a structural pure prefix.
`RejectIncompleteValidationMemo` is an opt-in strict policy that rejects only
when incompleteness occurred before that watershed.

The research defaults are 8 entries and 16 KiB per transaction. One BN254
four-pair result accounts for 948 bytes (128 bytes conservative entry overhead,
20 address/fork discriminator bytes, 768 input bytes, and 32 output bytes), so
the entry limit can retain eight such results within the byte limit. These
values are bounded experiment settings, not a proposed public-network
baseline. At the default 5,120 pool limit, `MaxPoolSize * MaxBytesPerTx` is 80
MiB of configured entry budget; fixed memo and map overhead is additional and
must be included in RSS measurements.

Defaults preserve the prior policy:

```text
MaxVerifyGas                    100000
MaxStateDependentVerifyGas      100000
CacheValidationPrecompiles      false
RejectIncompleteValidationMemo  false
ValidationMemoMaxEntries        8
ValidationMemoMaxBytes          16384
```

The corresponding CLI flags are under `framepool.*`. Raising
`MaxVerifyGas` continues to use the existing unsafe benchmark guard. The memo
is opt-in, while profiling and the default-equivalent state cap remain active
when it is off.

## Measurement corpus

`internal/framecorpus` and `devp2p rlpx frame-load` share deterministic
four-pair BN254 workloads. The pairing precompile charges 181,000 gas and the
program verifies both CALL success and its 32-byte true result before APPROVE.
Inputs vary per generated transaction and remain stable for resets of that
transaction. The corpus includes pure-first, state-first, state-selected input,
cheap-now/expensive-later, pure-EVM-before-state, and pure-only shapes.

Metrics report state-dependent gas, rejection and first-mutable categories,
memo hit/miss/actual-run/store/saturation (including before/after-watershed
incompleteness), strict incomplete-memo rejection, reset memo deltas, static
program drops, and profile mismatches. `cachedgas` means gas that was still
charged while CPU execution was skipped; it is not transaction gas saved.

Correctness qualification also covers transaction-global suffix charging,
prior-frame status/gas bridges, cross-frame warm access, blob `max_cost`
invalidation, precompile-address `EXTCODEHASH` dusting, repeated invalid KZG
proofs, exact memo limits, oversized inputs, and cross-frame saturation after
the watershed.

Reportable benchmark runs require a fresh process and datadir per arm, fixed
hardware and worker settings, source/binary/config/genesis provenance, raw JSON
and Prometheus snapshots, conservation checks, and RSS measurements. Local Go
benchmarks are smoke tests and must not be combined with reportable results.

## Current-format limitations

This implementation is a transition PoC that meters the first mutable read and
reuses pure precompile outputs. Revalidation still starts at PC 0, so a pure EVM
prefix that is not a precompile runs again. Existing privacy verifiers that
check state before proof verification receive a large state-dependent bound,
even when an exact-input memo can make resets faster. A low cap therefore
cannot be adopted as a public baseline from this PoC alone. Pure EVM replay,
cold-trie latency, node-wide reset scheduling, and asynchronous reset remain
separate problems.

The final design needs explicit `PURE_VERIFY` and `STATE_CHECK` frame boundaries.
A separate consensus and transaction-format proposal must decide:

1. wire encoding without claiming an unused flag bit;
2. how approval results combine;
3. bounded returndata and its commitment;
4. when a node may run the state check first;
5. the complete pure-program identity key;
6. mutable opcodes forbidden in a pure frame;
7. state-frame dependency declarations and validation gas/CPU pricing;
8. the relationship among pure, state-check, and state-growth gas limits; and
9. fan-out and scheduler bounds expressed in state-check cost.
