// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import { Endian } from "../Endian.sol";
import { BtcTxProof, BitcoinTx, BitcoinTxIn, BitcoinTxOut } from "../interfaces/BtcStructs.sol";

error TxMerkleRootMismatch(bytes32 blockTxRoot, bytes32 txRoot);
error ScriptMismatch(bytes expected, bytes actual);
error AmountMismatch(uint256 txoSats, uint256 expected);
error TxIDMismatch(bytes32 rawTxId, bytes32 txProofId);
error BlockHashMismatch(bytes32 blockHeader, bytes32 givenBlockHash);

error InvalidTxInHash(uint256 expected, uint256 actual);
error InvalidTxInIndex(uint32 expected, uint32 actual);

// BtcProof provides functions to prove things about Bitcoin transactions.
// Verifies merkle inclusion proofs, transaction IDs, and payment details.
library BtcProof {
    /**
     * @dev Validates that a given payment appears under a given block hash.
     *
     * This verifies all of the following:
     * 1. Raw transaction contains a transcation that pay X satoshis to the specified output script
     * 2. Raw transaction hashes to the given transaction ID.
     * 3. Transaction ID appears under transaction root (Merkle proof).
     * 4. Transaction root is part of the block header.
     * 5. Block header hashes to a given block hash.
     *
     * The caller must separately verify that the block hash is in the chain.
     *
     * Always returns true or reverts with a descriptive reason.
     */
    function validateExactOut(
        bytes32 blockHash,
        BtcTxProof calldata txProof,
        uint256 txOutIx,
        bytes calldata outputScript,
        uint256 satoshisExpected
    ) internal pure returns (bool) {
        // 5. Block header to block hash
        
        bytes32 blockHeaderBlockHash = getBlockHash(txProof.blockHeader);
        if (blockHeaderBlockHash != blockHash) revert BlockHashMismatch(blockHeaderBlockHash, blockHash);

        // 4. and 3. Transaction ID included in block
        bytes32 blockTxRoot = getBlockTxMerkleRoot(txProof.blockHeader);
        bytes32 txRoot = getTxMerkleRoot(
            txProof.txId,
            txProof.txIndex,
            txProof.txMerkleProof
        );
        if (blockTxRoot != txRoot) revert TxMerkleRootMismatch(blockTxRoot, txRoot);

        // 2. Raw transaction to TxID
        bytes32 rawTxId = getTxID(txProof.rawTx);
        if (rawTxId != txProof.txId) revert TxIDMismatch(rawTxId, txProof.txId);

        // 1. Finally, validate raw transaction pays stated recipient.
        BitcoinTx memory parsedTx = parseBitcoinTx(txProof.rawTx);
        BitcoinTxOut memory txo = parsedTx.outputs[txOutIx];
        // if the length are less than 32, then use bytes32 to compare.
        if  (txo.script.length <= 32 && outputScript.length <= 32) {
            if (bytes32(txo.script) != bytes32(outputScript)) revert ScriptMismatch(txo.script, outputScript);
        } else {
            if (keccak256(txo.script) != keccak256(outputScript)) revert ScriptMismatch(txo.script, outputScript);
        }
        if (txo.valueSats != satoshisExpected) revert AmountMismatch(txo.valueSats, satoshisExpected);

        // We've verified that blockHash contains a transaction with correct script
        // that sends at least satoshisExpected to the given hash.
        return true;
    }

    /**
     * @dev Validates that a given transfer of ordinal(s) appears under a given block hash.
     *
     * This verifies all of the following:
     * 1. Raw transaction contains a specific input (at index 0) that pays more than X to specific output (at index 0).
     * 2. Raw transaction hashes to the given transaction ID.
     * 3. Transaction ID appears under transaction root (Merkle proof).
     * 4. Transaction root is part of the block header.
     * 5. Block header hashes to a given block hash.
     *
     * The caller must separately verify that the block hash is in the chain.
     *
     * Always returns true or reverts with a descriptive reason.
     */
    function validateOrdinalTransfer(
        bytes32 blockHash,
        BtcTxProof calldata txProof,
        uint256 txInId,
        uint32 txInPrevTxIndex,
        bytes calldata outputScript,
        uint256 satoshisExpected
    ) internal pure returns (bool) {
        // 5. Block header to block hash
        
        bytes32 blockHeaderBlockHash = getBlockHash(txProof.blockHeader);
        if (blockHeaderBlockHash != blockHash) revert BlockHashMismatch(blockHeaderBlockHash, blockHash);

        // 4. and 3. Transaction ID included in block
        bytes32 blockTxRoot = getBlockTxMerkleRoot(txProof.blockHeader);
        bytes32 txRoot = getTxMerkleRoot(
            txProof.txId,
            txProof.txIndex,
            txProof.txMerkleProof
        );
        if (blockTxRoot != txRoot) revert TxMerkleRootMismatch(blockTxRoot, txRoot);

        // 2. Raw transaction to TxID
        bytes32 rawTxId = getTxID(txProof.rawTx);
        if (rawTxId != txProof.txId) revert TxIDMismatch(rawTxId, txProof.txId);

        // 1. Finally, validate raw transaction correctly transfers the ordinal(s).
        // Parse transaction
        BitcoinTx memory parsedTx = parseBitcoinTx(txProof.rawTx);
        BitcoinTxIn memory txInput = parsedTx.inputs[0];
        // Check if correct input transaction is used.
        if (txInId != txInput.prevTxID) revert InvalidTxInHash(txInId, txInput.prevTxID);
        // Check if correct index of that transaction is used.
        if (txInPrevTxIndex != txInput.prevTxIndex) revert InvalidTxInIndex(txInPrevTxIndex, txInput.prevTxIndex);

        BitcoinTxOut memory txo = parsedTx.outputs[0];
        // if the length are less than 32, then use bytes32 to compare.
        if  (txo.script.length <= 32 && outputScript.length <= 32) {
            if (bytes32(txo.script) != bytes32(outputScript)) revert ScriptMismatch(txo.script, outputScript);
        } else {
            if (keccak256(txo.script) != keccak256(outputScript)) revert ScriptMismatch(txo.script, outputScript);
        }
        // We allow for sending more because of the dust limit which may cause problems.
        if (txo.valueSats < satoshisExpected) revert AmountMismatch(txo.valueSats, satoshisExpected);

        // We've verified that blockHash contains a transaction with correct script
        // that sends at least satoshisExpected to the given hash.
        return true;
    }

    /**
     * @dev Compute a block hash given a block header.
     */
    function getBlockHash(bytes calldata blockHeader)
        internal
        pure
        returns (bytes32)
    {
        require(blockHeader.length == 80);
        bytes32 ret = sha256(bytes.concat(sha256(blockHeader)));
        return bytes32(Endian.reverse256(uint256(ret)));
    }

    /**
     * @dev Get the transactions merkle root given a block header.
     */
    function getBlockTxMerkleRoot(bytes calldata blockHeader)
        internal
        pure
        returns (bytes32)
    {
        require(blockHeader.length == 80);
        return bytes32(blockHeader[36:68]);
    }

    /**
     * @dev Recomputes the transactions root given a merkle proof.
     */
    function getTxMerkleRoot(
        bytes32 txId,
        uint256 txIndex,
        bytes calldata siblings
    ) internal pure returns (bytes32) {
        unchecked {

        bytes32 ret = bytes32(Endian.reverse256(uint256(txId)));
        uint256 len = siblings.length / 32;
        for (uint256 i = 0; i < len; ++i) {
            bytes32 s = bytes32(
                Endian.reverse256(
                    uint256(bytes32(siblings[i * 32:(i + 1) * 32]))  // i is small.
                )
            );
            if (txIndex & 1 == 0) {
                ret = doubleSha(abi.encodePacked(ret, s));
            } else {
                ret = doubleSha(abi.encodePacked(s, ret));
            }
            txIndex = txIndex >> 1;
        }
        return ret;

        }
    }

    /**
     * @dev Computes the ubiquitious Bitcoin SHA256(SHA256(x))
     */
    function doubleSha(bytes memory buf) internal pure returns (bytes32) {
        return sha256(bytes.concat(sha256(buf)));
    }

    /**
     * @dev Recomputes the transaction ID for a raw transaction.
     */
    function getTxID(bytes calldata rawTransaction)
        internal
        pure
        returns (bytes32)
    {
        bytes32 ret = doubleSha(rawTransaction);
        return bytes32(Endian.reverse256(uint256(ret)));
    }

    /**
     * @dev Parses a HASH-SERIALIZED Bitcoin transaction.
     *      This means no flags and no segwit witnesses.
     *
     *      Should only be done on verified transactions as the unchecked block allows
     *      for user controlled overflow but only if bad data is provided. A valid Bitcoin
     *      transaction will never behave like that.
     */
    function parseBitcoinTx(bytes calldata rawTx)
        internal
        pure
        returns (BitcoinTx memory ret)
    {
        // This unchecked block is safe because the offset is measured in the size of rawTx.
        // as such, it will be lower than type(uint256).max
        // Some people may try to make the varint fail but that isn't a valid Bitcoin transaction.
        // as such, it is already invalid.
        unchecked {

        ret.version = Endian.reverse32(uint32(bytes4(rawTx[0:4])));
        if (ret.version < 1 || ret.version > 2) {
            return ret; // invalid version
        }

        // Read transaction inputs
        uint256 offset = 4;
        uint256 nInputs;
        (nInputs, offset) = readVarInt(rawTx, offset);
        ret.inputs = new BitcoinTxIn[](nInputs);
        for (uint256 i = 0; i < nInputs; ++i) {
            BitcoinTxIn memory txIn;
            txIn.prevTxID = Endian.reverse256(
                uint256(bytes32(rawTx[offset:offset += 32]))
            );
            txIn.prevTxIndex = Endian.reverse32(
                uint32(bytes4(rawTx[offset:offset += 4]))
            );
            uint256 nInScriptBytes;
            ( nInScriptBytes, offset) = readVarInt(rawTx, offset);
            txIn.script = rawTx[offset:offset += nInScriptBytes];
            txIn.seqNo = Endian.reverse32(
                uint32(bytes4(rawTx[offset:offset += 4]))
            );
            ret.inputs[i] = txIn;
        }

        // Read transaction outputs
        uint256 nOutputs;
        (nOutputs, offset) = readVarInt(rawTx, offset);
        ret.outputs = new BitcoinTxOut[](nOutputs);
        for (uint256 i = 0; i < nOutputs; ++i) {
            BitcoinTxOut memory txOut;
            txOut.valueSats = Endian.reverse64(
                uint64(bytes8(rawTx[offset:offset += 8]))
            );
            uint256 nOutScriptBytes;
            (nOutScriptBytes, offset) = readVarInt(rawTx, offset);
            txOut.script = rawTx[offset:offset += nOutScriptBytes];
            ret.outputs[i] = txOut;
        }

        // Finally, read locktime, the last four bytes in the tx.
        ret.locktime = Endian.reverse32(
            uint32(bytes4(rawTx[offset:offset += 4]))
        );
        if (offset != rawTx.length) {
            return ret; // Extra data at end of transaction.
        }

        // Parsing complete, sanity checks passed, return success.
        ret.validFormat = true;
        return ret;

        }
    }

    /** Reads a Bitcoin-serialized varint = a u256 serialized in 1-9 bytes. */
    function readVarInt(bytes calldata buf, uint256 offset)
        internal
        pure
        returns (uint256 val, uint256 newOffset)
    {
        // The offset is bounded in size.
        unchecked {

        uint8 pivot = uint8(buf[offset]);
        if (pivot < 0xfd) {
            val = pivot;
            return (val, newOffset = offset + 1);
        }
        if (pivot == 0xfd) {
            val = Endian.reverse16(uint16(bytes2(buf[offset + 1:offset + 3])));
            return (val, newOffset = offset + 3);
        }
        if (pivot == 0xfe) {
            val = Endian.reverse32(uint32(bytes4(buf[offset + 1:offset + 5])));
            return (val, newOffset = offset + 5);
        }
        // pivot == 0xff
        val = Endian.reverse64(uint64(bytes8(buf[offset + 1:offset + 9])));
        return (val, newOffset = offset + 9);

        }
    }
}
