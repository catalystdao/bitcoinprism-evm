// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "forge-std/Test.sol";

import { BtcScript} from "../src/library/BtcScript.sol";

contract BtcProofTest is DSTest, BtcScript {

    BtcScript btcScript = new BtcScript();

    function testGetP2SH() public {
        bytes memory validP2SH = hex"a914ae2f3d4b06579b62574d6178c10c882b9150374087";
        bytes memory invalidP2SH1 = hex"a914ae2f3d4b06579b62574d6178c10c882b9150374086";
        bytes memory invalidP2SH2 = hex"a900ae2f3d4b06579b62574d6178c10c882b9150374087";

        assertEq(
            uint160(btcScript.decodeP2SH(validP2SH)),
            0x00ae2f3d4b06579b62574d6178c10c882b91503740
        );

        assertEq(uint160(btcScript.decodeP2SH(invalidP2SH1)), 0);
        assertEq(uint160(btcScript.decodeP2SH(invalidP2SH2)), 0);
    }
}
