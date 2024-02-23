// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./BitcoinOpcodes.sol";
import { Endian } from "../Endian.sol";

enum AddressType {
    UNKNOWN,
    P2PKH,
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR
}

/**
 * @notice A Parsed Script address
 */
struct BitcoinAddress {
    AddressType addressType;
    /** @dev P2PKH, address hash or P2SH, script hash. Is empty if segwit transaction */
    bytes20 legacyAddress;
    /** @dev Witness version */
    uint8 witnessVersion;
    /** @dev Witness Program */
    bytes witnessProgram;
}

/** 
 * @notice This contract implement helper functions for external actors 
 * when they encode or decode Bitcoin scripts.
 * @dev This contract is not intended for on-chain calls.
 */
contract BtcScript {

    //--- Bitcoin Script Decode Helpers ---//

    /**
     * @notice Global helper for decoding Bitcoin addresses
     */
    function getBitcoinAddress(bytes calldata script) external pure returns(BitcoinAddress memory btcAddress) {
        // Check if P2PKH
        bytes1 firstByte = script[0];
        if (firstByte == OP_DUB) {
            if (script.length == P2PKH_SCRIPT_LENGTH) {
                btcAddress.addressType = AddressType.P2PKH;
                btcAddress.legacyAddress = decodeP2PKH(script);
                return btcAddress;
            }
        } else if (firstByte == OP_HASH160) {
            if (script.length == P2SH_SCRIPT_LENGTH) {
                btcAddress.addressType = AddressType.P2SH;
                btcAddress.legacyAddress = decodeP2SH(script);
                return btcAddress;
            }
        } else {
            // This is likely a segwit transaction. Try decoding the witness program
            (int8 version, bytes calldata witPro) = decodeWitnessProgram(script);
            if (version != -1) {
                if (version == 0) {
                    uint256 witnessProgramLength = witPro.length;
                    if (witnessProgramLength == 20) {
                        btcAddress.addressType = AddressType.P2WPKH;
                    } else if (witnessProgramLength == 32) {
                        btcAddress.addressType = AddressType.P2WSH;
                    }
                } else if (version == 1) {
                    btcAddress.addressType = AddressType.P2TR;
                }
                btcAddress.witnessVersion = uint8(version);
                btcAddress.witnessProgram = witPro;
                return btcAddress;
            }
        }
    }

    /**
     * @dev Returns the script hash from a P2SH (pay to script hash) script out.
     * @return hash The recipient script hash, or 0 if verification failed.
     */
    function decodeP2SH(bytes calldata script)
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
     * @dev Returns the pubkey hash from a P2PKH (pay to pubkey hash) script out.
     * @return hash The recipient public key hash, or 0 if verification failed.
     */
    function decodeP2PKH(bytes calldata script)
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
    function decodeWitnessProgram(bytes calldata script)
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
        }
        // Currently the spec does not allow for other opcodes but the ones from 1 to 75, so the below is not valid
        // witness program pushes.
        // } else if (length_byte == uint8(OP_PUSHDATA1)) {
        //     uint8 length = uint8(bytes1(script[3]));
        //     if (script.length == length + 3) {
        //         return (version, script[3:]);
        //     }
        // } else if (length_byte == uint8(OP_PUSHDATA2)) {
        //     uint16 length = Endian.reverse16(uint16(bytes2(script[3:4])));
        //     if (script.length == length + 4) {
        //         return (version, script[4:]);
        //     }
        // } else if (length_byte == uint8(OP_PUSHDATA4)) {
        //     uint32 length = Endian.reverse32(uint32(bytes4(script[3:6])));
        //     if (script.length == length + 6) {
        //         return (version, script[6:]);
        //     }
        // }
        return (version = -1, script[0:0]);
    }
    

    //--- Bitcoin Script Encoding Helpers ---//


    /**
     * @notice Global helper for encoding Bitcoin scripts
     */
    function getBitcoinScript(BitcoinAddress calldata btcAddress) external pure returns(bytes memory script) {
        // Check if segwit
        if (btcAddress.addressType == AddressType.P2PKH) return scriptP2PKH(btcAddress.legacyAddress);
        if (btcAddress.addressType == AddressType.P2SH) return scriptP2SH(btcAddress.legacyAddress);
        if (btcAddress.addressType == AddressType.P2WPKH) {
            require(btcAddress.witnessVersion == 0, "WrongWitnessVersion");
            return scriptP2WPKH(btcAddress.witnessProgram);
        }
        if (btcAddress.addressType == AddressType.P2SH) {
            require(btcAddress.witnessVersion == 0, "WrongWitnessVersion");
            return scriptP2WSH(btcAddress.witnessProgram);
        }
        if (btcAddress.addressType == AddressType.P2TR) {
            require(btcAddress.witnessVersion == 1, "WrongWitnessVersion");
            return scriptP2TR(btcAddress.witnessProgram);
        }
    }

    /// @notice Get the associated script out for a P2PKH address
    function scriptP2PKH(bytes20 pHash) public pure returns(bytes memory) {
        // OP_DUB, OP_HASH160, <pubKeyHash 20>, OP_EQUALVERIFY, OP_CHECKSIG
        return bytes.concat(OP_DUB, OP_HASH160, PUSH_20, pHash, OP_EQUALVERIFY, OP_CHECKSIG);
    }

    /// @notice Get the associated script out for a P2SH address
    function scriptP2SH(bytes20 sHash) public pure returns(bytes memory) {
        // OP_HASH, <data 20>, OP_EQUAL
        return bytes.concat(OP_HASH160, PUSH_20, sHash, OP_EQUAL);
    }

    function scriptP2WPKH(bytes calldata pubkeyhash) public pure returns(bytes memory) {
        require(pubkeyhash.length == 20, "pubkey hash length");
        return scriptWitness(0, pubkeyhash);
    }

    function scriptP2WSH(bytes calldata witnessScript) public pure returns(bytes memory) {
        require(witnessScript.length == 32, "witness script hash length");
        return scriptWitness(0, witnessScript);
    }

    function scriptP2TR(bytes calldata witnessScript) public pure returns(bytes memory) {
    // TODO: Is there a fixed length for taproot?
        return scriptWitness(1, witnessScript);
    }

    function scriptWitness(uint8 witnessVersion, bytes calldata witnessProgram) public pure returns(bytes memory) {
        bytes1 witnessBytes;
        // Currently only 2 witness versions exist but this allows for future proofing.
        // The number of Bitcoin number opcodes only allow for number 0 through 16.
        require(witnessVersion <= 16, "witness version > 16");
        if (witnessVersion == 0) {
            witnessBytes = OP_0;
        } else {
            witnessBytes = bytes1(witnessVersion + uint8(LESS_THAN_OP_1));
        }
        // The length can't be longer than 75 bytes otherwise we should use another push opcode.
        uint8 witnessLength = uint8(witnessProgram.length);
        require(witnessLength <= 75, "witness length > 75");
        return bytes.concat(witnessBytes, bytes1(uint8(witnessLength)), witnessProgram);
    }
}