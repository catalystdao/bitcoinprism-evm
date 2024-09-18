// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "forge-std/Test.sol";

import "../src/BtcPrism.sol";
import "../src/BtcTxVerifier.sol";
import "../src/library/BtcProof.sol";

import { TooFewConfirmations } from "../src/interfaces/IBtcTxVerifier.sol";

contract BtcTxVerifierTest is DSTest {
    Vm vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // correct header for bitcoin block #717695
    // all bitcoin header values are little-endian:
    bytes constant b717695 = (
        hex"04002020"
        hex"edae5e1bd8a0e007e529fe33d099ebb7a82a06d6d63d0b000000000000000000"
        hex"f8aec519bcd878c9713dc8153a72fd62e3667c5ade70d8d0415584b8528d79ca"
        hex"0b40d961"
        hex"ab980b17"
        hex"3dcc4d5a"
    );

    function testVerifyTx() public {
        BtcPrism prism = new BtcPrism(
            736000, // start at block #736000
            0x00000000000000000002d52d9816a419b45f1f0efe9a9df4f7b64161e508323d,
            0,
            0x0,
            false
        );
        assertEq(prism.getLatestBlockHeight(), 736000);

        BtcTxVerifier verif = new BtcTxVerifier(prism);

        // validate payment 736000 #1
        bytes memory header736000 = (
            hex"04000020"
            hex"d8280f9ce6eeebd2e117f39e1af27cb17b23c5eae6e703000000000000000000"
            hex"31b669b35884e22c31b286ed8949007609db6cb50afe8b6e6e649e62cc24e19c"
            hex"a5657c62"
            hex"ba010917"
            hex"36d09865"
        );
        bytes memory txProof736 = (
            hex"d298f062a08ccb73abb327f01d2e2c6109a363ac0973abc497eec663e08a6a13"
            hex"2e64222ee84f7b90b3c37ed29e4576c41868c7dcf73b1183c1c84a73c3bb0451"
            hex"ea4cc81f31578f895bd3c14fcfdd9273173e754bddca44252f261e28ba814b8a"
            hex"d3199dac99561c60e9ea390d15633534de8864c7eb37512c6a6efa1e248e91e5"
            hex"fb0f53df4e177151d7b0a41d7a49d42f4dcf5984f6198b223112d20cf6ae41ed"
            hex"b0914821bd72a12b518dc94e140d651b7a93e5bb7671b3c8821480b0838740ab"
            hex"19d90729a753c500c9dc22cc7fec9a36f9f42597edbf15ccd1d68847cf76da67"
            hex"bc09b6091ec5863f23a2f4739e4c6ba28bb7ba9bcf2266527647194e0fccd94a"
            hex"e6925c8491e0ff7e5a7db9d35c5c15f1cccc49b082fc31b1cc0a364ca1ecc358"
            hex"d7ff70aa2af09f007a0aba4e1df6e850906d22a4c3cc23cd3b87ba0cb3a57e33"
            hex"fb1f9877e50b5cbb8b88b2db234687ea108ac91a232b2472f96f08f136a5eba4"
            hex"0b2be0cdd7773b1ddd2b847c14887d9005daf04da6188f9beeccab698dcc26b9"
        );
        bytes32 txId736 = 0x3667d5beede7d89e41b0ec456f99c93d6cc5e5caff4c4a5f993caea477b4b9b9;
        bytes memory tx736 = (
            hex"02000000"
            hex"01"
            hex"bb185dfa5b5c7682f4b2537fe2dcd00ce4f28de42eb4213c68fe57aaa264268b"
            hex"01000000"
            hex"17"
            hex"16001407bf360a5fc365d23da4889952bcb59121088ee1"
            hex"feffffff"
            hex"02"
            hex"8085800100000000"
            hex"17"
            hex"a914ae2f3d4b06579b62574d6178c10c882b9150374087"
            hex"1c20590500000000"
            hex"17"
            hex"a91415ecf89e95eb07fbc351b3f7f4c54406f7ee5c1087"
            hex"00000000"
        );
        bytes memory destScript = hex"a914ae2f3d4b06579b62574d6178c10c882b9150374087";

        BtcTxProof memory txP = BtcTxProof(
            header736000,
            txId736,
            1,
            txProof736,
            tx736
        );

        assertEq(verif.verifyPayment(1, 736000, txP, 0, destScript), 25200000);

        vm.expectRevert(abi.encodeWithSelector(TooFewConfirmations.selector, 1, 2));
        assertEq(verif.verifyPayment(2, 736000, txP, 0, destScript), 0);

        vm.expectRevert(abi.encodeWithSelector(ScriptMismatch.selector,  hex"a914ae2f3d4b06579b62574d6178c10c882b9150374087", hex"a91415ecf89e95eb07fbc351b3f7f4c54406f7ee5c1087"));
        assertEq(verif.verifyPayment(1, 736000, txP, 1, destScript), 0);

        vm.expectRevert(abi.encodeWithSelector(BlockHashMismatch.selector, 0x00000000000000000002d52d9816a419b45f1f0efe9a9df4f7b64161e508323d, 0x0000000000000000000000000000000000000000000000000000000000000000));
        assertEq(verif.verifyPayment(1, 700000, txP, 0, destScript), 0);
    }

    function testVerifySegwitTx() public {
        BtcPrism prism = new BtcPrism(
            831400, // start at block #736000
            0x00000000000000000002f2b8b266d44886b53142a93464b7042ca8b014d1fcfc,
            0,
            0x0,
            false
        );
        assertEq(prism.getLatestBlockHeight(), 831400);

        BtcTxVerifier verif = new BtcTxVerifier(prism);

        // validate payment 736000 #1
        bytes memory header831400 = (
            hex"0000fe21"
            hex"549c78d465a3402b49e88e280b2174802cfe48c3a7e502000000000000000000"
            hex"ef80671071bf2d1516297ffff61d3af4f6fd8b158cf93464fe55419b7de396a4"
            hex"77e4d565"
            hex"b1710317"
            hex"9e22dcb8"
        );
        bytes memory txProof39 = (
            hex"2a6578cf32e39d6d6a177f1e674783ae592fc92f47c4cbbb16ec56e8f4a6e5a2"
            hex"22901d5d09a682c4183d749cffdba2fa0c38177973c173808e141ec1fde30191"
            hex"3035b460ca24c7ed6eb91d4adb8937e6be0b5f56bc3b450ec1cf6e8f7f235189"
            hex"4f124488fe468b40bd00beacb317519830773fb451d75f0e05a0a7958e1dff84"
            hex"f6cb07c8d86bfa7715f0e2531a657f9b8aff3e87e620211425a408411bc6451b"
            hex"bf3843abde8440123f6bca0b89f9f69bd4add011b5b54391965968bce3210fd2"
            hex"a696e32181ff22de6d18cac6baabd769297e87385c68e629ecdc9824f1334b97"
            hex"d75730897ca8a28cf203db8f616eec625b090db2719d3b4ea49c49325a439e80"
            hex"bc239bca6af2c740125f21c83522d9e7875739fa207dd8b8ac2c71994530bf97"
            hex"31a314521ef37308185284b7c26dc4b9b3a6c41308e8d3a2350a8af6fc281be2"
            hex"79ff7a2e5af8c44afb6927dc545e7d19d0dd2a8937d1c02b2a6ac3e4994358f2"
            hex"b0afd6a0c5c725eb25fe25c814bd32d401d98f780e44bec9bab74696b2fd8791"
        );
        bytes32 txId39 = 0xf2abcea74b697724fd5578302716d2ea30d61f807d377de87cea53529f00f045;
        bytes memory tx39 = hex"010000000151bb1bc27cb75a4f1913d8a772d58d8f12843405c27d21aa6a24a2b0310ac02a0d00000000ffffffff1170e5310000000000160014321f4a352c69ce03b733006ff92621bc65cbd20c08c9010000000000160014aa61fff0b5be5965fd836c42c315881d3851910d225c0400000000002251202ed6f642338e96c9ca670d3e50d025dcbb1471c8ebcb21e6d4d054527a7a6d7f65230200000000002251208a1af857eb19aa1fbd5f9159352d602fa07626fb2eea1d9eda99a696a4fcc7c1d0a11000000000001600147f4614fbf219e184df08d5a9ded109a728b9e36021a21900000000001976a91426bd01d4b19f67e5efedb69b931f87cf5c553eb988ac383e0200000000002251206d7a1d236fb07c263823a9324687fda5c9e6f53735d5e914293f9043da3b0a0e21d1030000000000225120e95a72ba2cd9e8df717efdeea6dee029f274e7e4c8f6a0a14e29437347b53bcc40070400000000001600148e2dd25fc0791d8b1a75c360c9106ad79531e70d1ee5031b000000001976a91467b369972287134030c6081a450c999057a1aac888acd0334c0000000000225120e2d81f3a06f9e8928f109fdc3a6b5ada3f7cef0a6dfaf6d77be4c308f1078b0750ca1d0000000000160014b6de52ca1eaa748d12e4c0f90c5df46fcb7bc53055de0200000000001976a9146b4a6a6749bdd9c99b462423e6923c981e1c153d88acc9c21a000000000016001476c630f4e73d227f956b704f9db074425b77d24b953c1e000000000022512072d5021f7f999fd4dffba5954f081db22022fc44df930b7c7a2fd8c49e183120b6cc260000000000225120ec52aa9b1c31b034a828c5e12bd0c4c30a18802df339e9a981f96b7b7a6145c4bc45a20100000000220020e5c7c00d174631d2d1e365d6347b016fb87b6a0c08902d8e443989cb771fa7ec00000000";
        // bytes memory tx39 = 
        bytes memory destScript = hex"0014321f4a352c69ce03b733006ff92621bc65cbd20c";

        BtcTxProof memory txP = BtcTxProof(
            header831400,
            txId39,
            39,
            txProof39,
            tx39
        );

        assertEq(verif.verifyPayment(1, 831400, txP, 0, destScript), 3270000);
    }
}
