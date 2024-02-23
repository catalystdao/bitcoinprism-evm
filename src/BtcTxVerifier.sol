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
        bytes calldata destScriptHash,
        uint256 amountSats
    ) external view returns (bool) {
        {
            uint256 currentHeight = mirror.getLatestBlockHeight();

            if (currentHeight < blockNum) revert NoBlock(currentHeight, blockNum);

            if (currentHeight <= minConfirmations + blockNum) revert TooFewConfirmations(currentHeight - blockNum, minConfirmations);
        }

        bytes32 blockHash = mirror.getBlockHash(blockNum);

        if(
            !BtcProof.validateScriptMatch(
                blockHash,
                inclusionProof,
                txOutIx,
                destScriptHash,
                amountSats
            )
        ) revert InvalidProof();

        return true;
    }
}
