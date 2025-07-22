// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/utils/StringUtils.sol";

contract StringUtilsTest is Test {
    function test_splitCommaSeparated_singleURL() public {
        string memory input =
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 1, "Should return one element");
        assertEq(
            result[0],
            "https://github.com/flashbots/flashbots-images/commit/a5aa6c75fbecc4b88faf4886cbd3cb2c667f4a8c",
            "Element should match input URL"
        );
    }

    function test_splitCommaSeparated_multipleURLs() public {
        string memory input =
            "https://github.com/flashbots/mev-boost/commit/7fb1e6f8f96b55c0f672b0b66b61e7f10e1b6e8a,https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 2, "Should return two elements");
        assertEq(
            result[0],
            "https://github.com/flashbots/mev-boost/commit/7fb1e6f8f96b55c0f672b0b66b61e7f10e1b6e8a",
            "First element should be first URL"
        );
        assertEq(
            result[1],
            "https://ipfs.io/ipfs/bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly",
            "Second element should be second URL"
        );
    }

    function test_splitCommaSeparated_trimsWhitespaceURLs() public {
        string memory input =
            "  https://github.com/ethereum/go-ethereum/commit/9bbb9df18529f495f1312e94db22ddcf3e3022f8 , https://github.com/flashbots/builder/commit/d8e2d3e5f8ad7f8dd8e99e7e023e8e5e4bbbc8fb  ,https://ipfs.io/ipfs/bafkreigjpewirtzmt2ggqx7zqd5g5eqrtcnfli5oobqp7w3s2tagtusomy ";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 3, "Should return three elements");
        assertEq(
            result[0],
            "https://github.com/ethereum/go-ethereum/commit/9bbb9df18529f495f1312e94db22ddcf3e3022f8",
            "First element should be trimmed URL"
        );
        assertEq(
            result[1],
            "https://github.com/flashbots/builder/commit/d8e2d3e5f8ad7f8dd8e99e7e023e8e5e4bbbc8fb",
            "Second element should be trimmed URL"
        );
        assertEq(
            result[2],
            "https://ipfs.io/ipfs/bafkreigjpewirtzmt2ggqx7zqd5g5eqrtcnfli5oobqp7w3s2tagtusomy",
            "Third element should be trimmed URL"
        );
    }

    function test_splitCommaSeparated_emptyString() public {
        string memory input = "";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 1, "Should return one element for empty string");
        assertEq(result[0], "", "Element should be empty string");
    }

    function test_splitCommaSeparated_leadingAndTrailingCommasURLs() public {
        string memory input =
            ",https://github.com/flashbots/rbuilder/commit/c2e3d7c5f8ad7f8dd8e99e7e023e8e5e4bbbc8fb,https://ipfs.io/ipfs/bafybeif7l5k6vk6kpnfsc3biswihqz3le5ngnf47mj3lzrjbdh6jmqnzyi,";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 4, "Should return four elements");
        assertEq(result[0], "", "First element should be empty");
        assertEq(
            result[1],
            "https://github.com/flashbots/rbuilder/commit/c2e3d7c5f8ad7f8dd8e99e7e023e8e5e4bbbc8fb",
            "Second element should be first URL"
        );
        assertEq(
            result[2],
            "https://ipfs.io/ipfs/bafybeif7l5k6vk6kpnfsc3biswihqz3le5ngnf47mj3lzrjbdh6jmqnzyi",
            "Third element should be second URL"
        );
        assertEq(result[3], "", "Fourth element should be empty");
    }

    function test_splitCommaSeparated_onlyCommas() public {
        string memory input = ",,,";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 4, "Should return four empty elements");
        for (uint256 i = 0; i < result.length; i++) {
            assertEq(result[i], "", "Each element should be empty string");
        }
    }

    function test_splitCommaSeparated_spacesOnly() public {
        string memory input = "   ,  , ";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 3, "Should return three elements");
        for (uint256 i = 0; i < result.length; i++) {
            assertEq(result[i], "", "Each element should be empty string after trimming");
        }
    }

    function test_splitCommaSeparated_variousURLs() public {
        string memory input =
            "https://github.com/flashbots/rollup-boost/commit/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0, https://github.com/paradigmxyz/reth/commit/b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0 ,https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 3, "Should return three elements");
        assertEq(
            result[0],
            "https://github.com/flashbots/rollup-boost/commit/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "First element should be first URL"
        );
        assertEq(
            result[1],
            "https://github.com/paradigmxyz/reth/commit/b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
            "Second element should be second URL"
        );
        assertEq(
            result[2],
            "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            "Third element should be third URL"
        );
    }

    function test_splitCommaSeparated_URLsWithQueryStrings() public {
        string memory input =
            "https://github.com/flashbots/mev-boost-relay/commit/e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0?ref=main, https://ipfs.io/ipfs/bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq?filename=wiki.html";
        string[] memory result = StringUtils.splitCommaSeparated(input);
        assertEq(result.length, 2, "Should return two elements");
        assertEq(
            result[0],
            "https://github.com/flashbots/mev-boost-relay/commit/e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0?ref=main",
            "First element should be first URL with query"
        );
        assertEq(
            result[1],
            "https://ipfs.io/ipfs/bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq?filename=wiki.html",
            "Second element should be second URL with query"
        );
    }
}
