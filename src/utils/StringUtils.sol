// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title StringUtils
/// @notice Utility library for string operations
library StringUtils {
    /// @notice Splits a comma-separated string into a string[] array
    /// @dev Also trims leading and trailing whitespace from each segment
    /// @param input The input string to split
    /// @return An array of strings, each representing a segment of the input string
    function splitCommaSeparated(string memory input) internal pure returns (string[] memory) {
        bytes memory strBytes = bytes(input);
        uint256 segments = 1;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == ",") {
                segments++;
            }
        }
        string[] memory parts = new string[](segments);
        uint256 lastIndex = 0;
        uint256 partIdx = 0;
        for (uint256 i = 0; i <= strBytes.length; i++) {
            if (i == strBytes.length || strBytes[i] == ",") {
                // Trim leading/trailing whitespace
                uint256 start = lastIndex;
                uint256 end = i;
                // Trim leading spaces
                while (start < end && strBytes[start] == " ") {
                    start++;
                }
                // Trim trailing spaces
                while (end > start && strBytes[end - 1] == " ") {
                    end--;
                }
                bytes memory part = new bytes(end - start);
                for (uint256 j = 0; j < end - start; j++) {
                    part[j] = strBytes[start + j];
                }
                parts[partIdx] = string(part);
                partIdx++;
                lastIndex = i + 1;
            }
        }
        return parts;
    }

    /// @notice Checks if a string is empty
    /// @param str The string to check
    /// @return True if the string is empty, false otherwise
    function isEmpty(string memory str) internal pure returns (bool) {
        return bytes(str).length == 0;
    }
}
