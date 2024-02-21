# Bitcoin Prism

Bitcoin Prism is a fork of [Bitcoin Mirror](https://github.com/dcposch/BtcPrism/blob/master/README.md). Bitcoin Prism is intended to run on a single block chain which can then be queried from other chains to check for the existence of a valid proof. If claims against the Bitcoin network is make in an optimistic fashion, it allows for very effecient scaling.

## Bitcoin Prism tracks Bitcoin on Ethereum

Bitcoin's block headers contain a merkle root of all transactions within. By verifying the block headers, we can use the merkle root to prove inclusion of a transaction in the Bitcoin network.

By examining the out scripts of the transactions, we can prove that a payment was made.

## Quick Start

### Compile and test the contract

Install [Forge](https://getfoundry.sh/). Then:

```
forge test -vvv
```


### Deploy the contract

Ensure `ETHERSCAN_API_KEY` is set. Then, run the following to deploy and verify.

```
cd packages/contracts
forge script -f $RPC_URL --private-key $PK -s 'run(bool)' --broadcast --verify  DeployBtcPrism true
```

Run with `false` for a deployment tracking the Bitcoin testnet rather than mainnet.