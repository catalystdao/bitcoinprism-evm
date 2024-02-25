// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import { IBtcPrism } from "./interfaces/IBtcPrism.sol";
import { IBtcTxVerifier } from "./interfaces/IBtcTxVerifier.sol";
import { BtcProof, BtcTxProof } from "./library/BtcProof.sol";
import { NoBlock, TooFewConfirmations, InvalidProof } from "./interfaces/IBtcTxVerifier.sol";

// BtcVerifier implements a merkle proof that a Bitcoin payment succeeded. It
// uses BtcPrism as a source of truth for which Bitcoin block hashes are in the
// canonical chain.
contract BtcTxVerifier is IBtcTxVerifier {
    IBtcPrism public immutable mirror;

    constructor(IBtcPrism _mirror) {
        mirror = _mirror;
    }

    function verifyPayment(
        uint256 minConfirmations,
        uint256 blockNum,
        BtcTxProof calldata inclusionProof,
        uint256 txOutIx,
        bytes calldata outputScript
    ) external view returns (uint256 sats) {
        {
            uint256 currentHeight = mirror.getLatestBlockHeight();

            if (currentHeight < blockNum) revert NoBlock(currentHeight, blockNum);

            unchecked {
                if (currentHeight + 1 - blockNum < minConfirmations) revert TooFewConfirmations(currentHeight + 1 - blockNum, minConfirmations);
            }
        }

        bytes32 blockHash = mirror.getBlockHash(blockNum);

        return sats = BtcProof.validateExactOut(
            blockHash,
            inclusionProof,
            txOutIx,
            outputScript
        );
    }

    function verifyOrdinal(
        uint256 minConfirmations,
        uint256 blockNum,
        BtcTxProof calldata inclusionProof,
        uint256 txInId,
        uint32 txInPrevTxIndex,
        bytes calldata outputScript,
        uint256 amountSats
    ) external view returns (bool) {
        {
            uint256 currentHeight = mirror.getLatestBlockHeight();

            if (currentHeight < blockNum) revert NoBlock(currentHeight, blockNum);

            unchecked {
                if (currentHeight + 1 - blockNum < minConfirmations) revert TooFewConfirmations(currentHeight + 1 - blockNum, minConfirmations);
            }
        }

        bytes32 blockHash = mirror.getBlockHash(blockNum);

        if(
            !BtcProof.validateOrdinalTransfer(
                blockHash,
                inclusionProof,
                txInId,
                txInPrevTxIndex,
                outputScript,
                amountSats
            )
        ) revert InvalidProof();

        return true;
    }
}
