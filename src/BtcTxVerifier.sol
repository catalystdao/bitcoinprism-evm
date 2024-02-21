// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import { IBtcPrism } from "./interfaces/IBtcPrism.sol";
import { IBtcTxVerifier } from "./interfaces/IBtcTxVerifier.sol";
import { BtcProofUtils } from "./BtcProofUtils.sol";

//
//                                        #
//                                       # #
//                                      # # #
//                                     # # # #
//                                    # # # # #
//                                   # # # # # #
//                                  # # # # # # #
//                                 # # # # # # # #
//                                # # # # # # # # #
//                               # # # # # # # # # #
//                              # # # # # # # # # # #
//                                   # # # # # #
//                               +        #        +
//                                ++++         ++++
//                                  ++++++ ++++++
//                                    +++++++++
//                                      +++++
//                                        +
//
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
            uint256 mirrorHeight = mirror.getLatestBlockHeight();

            require(
                mirrorHeight >= blockNum,
                "Bitcoin Mirror doesn't have that block yet"
            );

            require(
                mirrorHeight + 1 >= minConfirmations + blockNum,
                "Not enough Bitcoin block confirmations"
            );
        }

        bytes32 blockHash = mirror.getBlockHash(blockNum);

        require(
            BtcProofUtils.validateScriptMatch(
                blockHash,
                inclusionProof,
                txOutIx,
                destScriptHash,
                amountSats
            ),
            "Invalid transaction proof"
        );

        return true;
    }
}
