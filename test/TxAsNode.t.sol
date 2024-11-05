// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "forge-std/Test.sol";

import "../src/Endian.sol";
import "../src/BtcPrism.sol";
import { BtcProof } from "../src/library/BtcProof.sol";

contract TxAsNodeTest is DSTest {
    Vm vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function getTxMerkleRoot(
        bytes32 txId,
        uint256 txIndex,
        bytes calldata siblings
    ) external pure returns (bytes32) {
        return BtcProof.getTxMerkleRoot(
            txId,
            txIndex,
            siblings
        );
    }

    function splitTransaction(
        bytes calldata rawTx
    ) external pure returns(bytes32 a, bytes32 b) {
        require(rawTx.length == 64);
        a = bytes32(rawTx[0:32]);
        b = bytes32(rawTx[32:64]);
    }

    // 64 bytes long transaction
    bytes constant smallTransaction = (
        hex"02000000" // Version flag, length: 4
        hex"01" // number of inputs, 1 is needed. length 5
        hex"b572b2c8c43737c1b9e7be57b742b939eaa58fb55df5d91f5a41d48c6706bda8" hex"00000000" hex"00" hex"" hex"fdffffff" // txid, outputIndex, script length, sequence, length 46
        hex"01" // number of outputs. Can be 1-2. length 47
        hex"9cfb050000000000" hex"04" hex"00000000" // value, outscript length, outscript, length, length 60
        hex"e3d10000" // locktime, length 64
    );

    // Is big endian.
    bytes32 constant smallTransactionId = 0x623d75f0edf34ac4f3f4ec29c2d96a08ca2479410c1bef2fb0abe46203231b3d;

    bytes32 merkleRoot = bytes32(Endian.reverse256(uint256(smallTransactionId)));

    // all bitcoin header values are little-endian:
    bytes customBlockHeader = bytes.concat(
        hex"04002020"
        hex"edae5e1bd8a0e007e529fe33d099ebb7a82a06d6d63d0b000000000000000000", // prev block.
        merkleRoot,
        hex"0b40d961"
        hex"ab980b17"
        hex"3dcc4d5a"
    );

    function testConstructionFunctionLength() public {
        assertEq(smallTransaction.length, 64);
    }

    // The transaction itself is a valid transaction. Lets verify its inclusion.
    function testVerifyTransactionaAsId() public {
        bytes32 txRoot = this.getTxMerkleRoot(
            smallTransactionId, 
            0,
            hex""
        );

        assertEq(txRoot, merkleRoot);
    }

    function testRevertVerifyTransactionAsSiblings() public {
        (bytes32 a, bytes32 b) = this.splitTransaction(smallTransaction);
        assertEq(sha256(abi.encodePacked(a, b)), smallTransactionId, "Tx not split correctly");

        vm.expectRevert(abi.encodeWithSignature(
            "InvalidMerkleNodePair(uint256,bytes32,bytes32)",
            0,
            a,
            b
        ));
        bytes32 txRoot = this.getTxMerkleRoot(
            bytes32(Endian.reverse256(uint256(a))), 
            0,
            bytes.concat(bytes32(Endian.reverse256(uint256(b))))
        );
    }

    function testRevertVerifyTransactionAsSiblings2() public {
        (bytes32 a, bytes32 b) = this.splitTransaction(smallTransaction);
        assertEq(sha256(abi.encodePacked(a, b)), smallTransactionId, "Tx not split correctly");

        vm.expectRevert(abi.encodeWithSignature(
            "InvalidMerkleNodePair(uint256,bytes32,bytes32)",
            1,
            b,
            a
        ));
        bytes32 txRoot = this.getTxMerkleRoot(
            bytes32(Endian.reverse256(uint256(b))),
            1,
            bytes.concat(bytes32(Endian.reverse256(uint256(a))))
        );
    }

    /** @notice Realistically, we shouldn't be able to fuzz for a valid transaction. */
    /// forge-config: default.fuzz.runs = 10000
    function testFuzzForValidDecodedNodePair(bytes32 a, bytes32 b) public {
        bytes memory rawTx = bytes.concat(a, b);
        require(rawTx.length == 64);
        bool isValid = BtcProof.checkIfBitcoinTransaction(rawTx);

        assertTrue(!isValid);
    }
}
