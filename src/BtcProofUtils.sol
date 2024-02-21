// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./BitcoinOpcodes.sol";
import "./Endian.sol";
import "./interfaces/BtcTxProof.sol";

/**
 * @dev A parsed (but NOT fully validated) Bitcoin transaction.
 */
struct BitcoinTx {
    /**
     * @dev Whether we successfully parsed this Bitcoin TX, valid version etc.
     *      Does NOT check signatures or whether inputs are unspent.
     */
    bool validFormat;
    /**
     * @dev Version. Must be 1 or 2.
     */
    uint32 version;
    /**
     * @dev Each input spends a previous UTXO.
     */
    BitcoinTxIn[] inputs;
    /**
     * @dev Each output creates a new UTXO.
     */
    BitcoinTxOut[] outputs;
    /**
     * @dev Locktime. Either 0 for no lock, blocks if <500k, or seconds.
     */
    uint32 locktime;
}

struct BitcoinTxIn {
    /** @dev Previous transaction. */
    uint256 prevTxID;
    /** @dev Specific output from that transaction. */
    uint32 prevTxIndex;
    /** @dev Mostly useless for tx v1, BIP68 Relative Lock Time for tx v2. */
    uint32 seqNo;
    /** @dev Input script, spending a previous UTXO. */
    bytes script;
}

/**
 * @notice A Parsed Script address
 */
struct BitcoinAddress {
    /** @dev P2PKH, address hash or P2SH, script hash. Is empty if segwit transaction */
    bytes20 legacyAddress;
    /** @dev Witness version */
    uint8 witnessVersion;
    /** @dev Witness Program */
    bytes witnessProgram;
}

struct BitcoinTxOut {
    /** @dev TXO value, in satoshis */
    uint64 valueSats;
    /** @dev Output script.  */
    bytes script;
}

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
// BtcProofUtils provides functions to prove things about Bitcoin transactions.
// Verifies merkle inclusion proofs, transaction IDs, and payment details.
library BtcProofUtils {
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
    function validateScriptMatch(
        bytes32 blockHash,
        BtcTxProof calldata txProof,
        uint256 txOutIx,
        bytes calldata outputScript,
        uint256 satoshisExpected
    ) internal pure returns (bool) {
        // 5. Block header to block hash
        require(
            getBlockHash(txProof.blockHeader) == blockHash,
            "Block hash mismatch"
        );

        // 4. and 3. Transaction ID included in block
        bytes32 blockTxRoot = getBlockTxMerkleRoot(txProof.blockHeader);
        bytes32 txRoot = getTxMerkleRoot(
            txProof.txId,
            txProof.txIndex,
            txProof.txMerkleProof
        );
        require(blockTxRoot == txRoot, "Tx merkle root mismatch");

        // 2. Raw transaction to TxID
        require(getTxID(txProof.rawTx) == txProof.txId, "Tx ID mismatch");

        // 1. Finally, validate raw transaction pays stated recipient.
        BitcoinTx memory parsedTx = parseBitcoinTx(txProof.rawTx);
        BitcoinTxOut memory txo = parsedTx.outputs[txOutIx];
        // if the length are less than 32, then use bytes32 to compare.
        if  (txo.script.length <= 32 && outputScript.length <= 32) {
            require(bytes32(txo.script) == bytes32(outputScript), "Script mismatch");
        } else {
            require(keccak256(txo.script) == keccak256(outputScript), "Script mismatch");
        }
        require(txo.valueSats == satoshisExpected, "Amount mismatch");

        // We've verified that blockHash contains a transaction with correct script
        // that sends at least satoshisExpected to the given hash.
        return true;
    }

    /**
     * @dev Compute a block hash given a block header.
     */
    function getBlockHash(bytes calldata blockHeader)
        public
        pure
        returns (bytes32)
    {
        require(blockHeader.length == 80);
        bytes32 ret = sha256(abi.encodePacked(sha256(blockHeader)));
        return bytes32(Endian.reverse256(uint256(ret)));
    }

    /**
     * @dev Get the transactions merkle root given a block header.
     */
    function getBlockTxMerkleRoot(bytes calldata blockHeader)
        public
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
    ) public pure returns (bytes32) {
        bytes32 ret = bytes32(Endian.reverse256(uint256(txId)));
        uint256 len = siblings.length / 32;
        for (uint256 i = 0; i < len; i++) {
            bytes32 s = bytes32(
                Endian.reverse256(
                    uint256(bytes32(siblings[i * 32:(i + 1) * 32]))
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

    /**
     * @dev Computes the ubiquitious Bitcoin SHA256(SHA256(x))
     */
    function doubleSha(bytes memory buf) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(buf)));
    }

    /**
     * @dev Recomputes the transaction ID for a raw transaction.
     */
    function getTxID(bytes calldata rawTransaction)
        public
        pure
        returns (bytes32)
    {
        bytes32 ret = doubleSha(rawTransaction);
        return bytes32(Endian.reverse256(uint256(ret)));
    }

    /**
     * @dev Parses a HASH-SERIALIZED Bitcoin transaction.
     *      This means no flags and no segwit witnesses.
     */
    function parseBitcoinTx(bytes calldata rawTx)
        public
        pure
        returns (BitcoinTx memory ret)
    {
        ret.version = Endian.reverse32(uint32(bytes4(rawTx[0:4])));
        if (ret.version < 1 || ret.version > 2) {
            return ret; // invalid version
        }

        // Read transaction inputs
        uint256 offset = 4;
        uint256 nInputs;
        (nInputs, offset) = readVarInt(rawTx, offset);
        ret.inputs = new BitcoinTxIn[](nInputs);
        for (uint256 i = 0; i < nInputs; i++) {
            BitcoinTxIn memory txIn;
            txIn.prevTxID = Endian.reverse256(
                uint256(bytes32(rawTx[offset:offset + 32]))
            );
            offset += 32;
            txIn.prevTxIndex = Endian.reverse32(
                uint32(bytes4(rawTx[offset:offset + 4]))
            );
            offset += 4;
            uint256 nInScriptBytes;
            (nInScriptBytes, offset) = readVarInt(rawTx, offset);
            txIn.script = rawTx[offset:offset + nInScriptBytes];
            offset += nInScriptBytes;
            txIn.seqNo = Endian.reverse32(
                uint32(bytes4(rawTx[offset:offset + 4]))
            );
            offset += 4;
            ret.inputs[i] = txIn;
        }

        // Read transaction outputs
        uint256 nOutputs;
        (nOutputs, offset) = readVarInt(rawTx, offset);
        ret.outputs = new BitcoinTxOut[](nOutputs);
        for (uint256 i = 0; i < nOutputs; i++) {
            BitcoinTxOut memory txOut;
            txOut.valueSats = Endian.reverse64(
                uint64(bytes8(rawTx[offset:offset + 8]))
            );
            offset += 8;
            uint256 nOutScriptBytes;
            (nOutScriptBytes, offset) = readVarInt(rawTx, offset);
            txOut.script = rawTx[offset:offset + nOutScriptBytes];
            offset += nOutScriptBytes;
            ret.outputs[i] = txOut;
        }

        // Finally, read locktime, the last four bytes in the tx.
        ret.locktime = Endian.reverse32(
            uint32(bytes4(rawTx[offset:offset + 4]))
        );
        offset += 4;
        if (offset != rawTx.length) {
            return ret; // Extra data at end of transaction.
        }

        // Parsing complete, sanity checks passed, return success.
        ret.validFormat = true;
        return ret;
    }

    /** Reads a Bitcoin-serialized varint = a u256 serialized in 1-9 bytes. */
    function readVarInt(bytes calldata buf, uint256 offset)
        public
        pure
        returns (uint256 val, uint256 newOffset)
    {
        uint8 pivot = uint8(buf[offset]);
        if (pivot < 0xfd) {
            val = pivot;
            newOffset = offset + 1;
        } else if (pivot == 0xfd) {
            val = Endian.reverse16(uint16(bytes2(buf[offset + 1:offset + 3])));
            newOffset = offset + 3;
        } else if (pivot == 0xfe) {
            val = Endian.reverse32(uint32(bytes4(buf[offset + 1:offset + 5])));
            newOffset = offset + 5;
        } else {
            // pivot == 0xff
            val = Endian.reverse64(uint64(bytes8(buf[offset + 1:offset + 9])));
            newOffset = offset + 9;
        }
    }

    //--- Public Address Helpers ---//

    /**
     * Global helper for decoding Bitcoin addresses.
     */
    function getBitcoinAddress(bytes calldata script) external pure returns(BitcoinAddress memory btcAddress) {
        // Check if P2PKH
        bytes1 firstByte = script[0];
        if (firstByte == OP_DUB) {
            if (script.length == P2PKH_SCRIPT_LENGTH) {
                btcAddress.legacyAddress = getP2PKH(script);
                return btcAddress;
            }
        } else if (firstByte == OP_HASH160) {
            if (script.length == P2SH_SCRIPT_LENGTH) {
                btcAddress.legacyAddress = getP2SH(script);
                return btcAddress;
            }
        } else {
            // This is likely a segwit transaction. Try decoding the witness program
            (int8 version, bytes calldata witPro) = getWitnessProgram(script);
            if (version >= 0) {
                btcAddress.witnessVersion = uint8(version);
                btcAddress.witnessProgram = witPro;
                return btcAddress;
            }
        }
    }

    /// @notice Get the associated script out for a P2SH address
    function getScriptForP2SH(bytes20 sHash) external pure returns(bytes memory) {
        // OP_HASH, <data 20>, OP_EQUAL
        return bytes.concat(OP_HASH160, PUSH_20, sHash, OP_EQUAL);
    }

    /// @notice Get the associated script out for a P2PKH address
    function getScriptForP2PKH(bytes20 pHash) external pure returns(bytes memory) {
        // OP_DUB, OP_HASH160, <pubKeyHash 20>, OP_EQUALVERIFY, OP_CHECKSIG
        return bytes.concat(OP_DUB, OP_HASH160, PUSH_20, pHash, OP_EQUALVERIFY, OP_CHECKSIG);
    }

    function getP2WPKH(bytes calldata pubkeyhash) external pure returns(bytes memory) {
        require(pubkeyhash.length == 20, "pubkey hash length");
        return getScriptForWitness(0, pubkeyhash);
    }

    function getP2WSH(bytes calldata witnessScript) external pure returns(bytes memory) {
        require(witnessScript.length != 20, "witness script hash length");
        return getScriptForWitness(0, witnessScript);
    }

    function getP2TR(bytes calldata witnessScript) external pure returns(bytes memory) {
        return getScriptForWitness(1, witnessScript);
    }

    function getScriptForWitness(uint8 witnessVersion, bytes calldata witnessProgram) public pure returns(bytes memory) {
        bytes1 witnessBytes;
        require(witnessVersion <= 16, "witness version > 16");
        if (witnessVersion == 0) {
            witnessBytes = OP_0;
        } else {
            witnessBytes = bytes1(witnessVersion + uint8(LESS_THAN_OP_1));
        }
        return bytes.concat(witnessBytes, bytes1(uint8(witnessProgram.length)), witnessProgram);
    }

    /**
     * @dev Returns the script hash from a P2SH (pay to script hash) tx.
     * @return hash The recipient script hash, or 0 if verification failed.
     */
    function getP2SH(bytes calldata script)
        public
        pure
        returns (bytes20)
    {
        if (script.length != P2SH_SCRIPT_LENGTH) {
            return 0;
        }
        // OP_HASH <data 20> OP_EQUAL
        if (script[0] != OP_HASH160 || script[1] != PUSH_20 || script[22] != OP_EQUAL) {
            return 0;
        }
        return bytes20(script[P2SH_ADDRESS_START:P2SH_ADDRESS_END]);
    }

    /**
     * @dev Returns the address hash from a P2PKH (pay to pubkey hash) tx.
     * @return hash The recipient public key hash, or 0 if verification failed.
     */
    function getP2PKH(bytes calldata script)
        public
        pure
        returns (bytes20)
    {
        if (script.length != P2PKH_SCRIPT_LENGTH) {
            return 0;
        }
        // OP_DUB OP_HASH160 <pubKeyHash 20> OP_EQUALVERIFY OP_CHECKSIG
        if (script[0] != OP_DUB || script[1] != OP_HASH160 || script[2] != PUSH_20 || script[23] != OP_EQUALVERIFY || script[24] != OP_CHECKSIG) {
            return 0;
        }
        return bytes20(script[P2PKH_ADDRESS_START:P2PKH_ADDRESS_END]);
    }

    /**
     * @dev Returns the witness program segwit tx.
     * @return version The script version, or -1 if verification failed.
     * @return hash The witness program, or nothing if verification failed.
     */
    function getWitnessProgram(bytes calldata script)
        public
        pure
        returns (int8 version, bytes calldata)
    {
        bytes1 versionBytes1 = script[0];
        if (versionBytes1 == OP_0) {
            version = 0;
        } else if ((uint8(OP_1) <= uint8(versionBytes1) && uint8(versionBytes1) <= uint8(OP_16))) {
            unchecked {
                version = int8(uint8(versionBytes1)) - int8(uint8(LESS_THAN_OP_1));
            }
        } else {
            return (version = -1, script[0:0]);
        }
        // Check that the length is given and correct.
        uint8 length_byte = uint8(bytes1(script[1]));
        // Check if the length is between 1 and 75. If it is more than 75, we need to decode the length in a different want.
        if (1 <= length_byte && length_byte <= 75) {
            if (script.length == length_byte + 2) {
                return (version, script[2:]);
            }
        } else if (length_byte == uint8(OP_PUSHDATA1)) {
            uint8 length = uint8(bytes1(script[3]));
            if (script.length == length + 3) {
                return (version, script[3:]);
            }
        } else if (length_byte == uint8(OP_PUSHDATA2)) {
            uint16 length = Endian.reverse16(uint16(bytes2(script[3:4])));
            if (script.length == length + 4) {
                return (version, script[4:]);
            }
        } else if (length_byte == uint8(OP_PUSHDATA4)) {
            uint32 length = Endian.reverse32(uint32(bytes4(script[3:6])));
            if (script.length == length + 6) {
                return (version, script[6:]);
            }
        }
        return (version = -1, script[0:0]);
    }
}
