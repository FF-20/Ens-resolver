// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./SupportsInterface.sol";
import "./IExtendedResolver.sol";
import "./SignatureVerifier.sol";

interface IResolverService {
    function resolve(
        bytes calldata name,
        bytes calldata data
    )
        external
        view
        returns (bytes memory result, uint64 expires, bytes memory sig);
}

contract OffchainResolver is IExtendedResolver, SupportsInterface {
    string public url;
    mapping(address=>bool) public signers;

    event NewSigners(address[] signers);
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    constructor(string memory _url, address[] memory _signers) {
        url = _url;
        for(uint i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        emit NewSigners(_signers);
    }


    function makeSignatureHash(address target, uint64 expires, bytes memory request, bytes memory result) external pure returns(bytes32) {
        return SignatureVerifier.makeSignatureHash(target, expires, request, result);
    } 

    function resolve(bytes calldata name, bytes calldata data) external override view returns(bytes memory) {
        bytes memory callData = abi.encodePacked(name, data);
        string[] memory urls = new string[](1);
        urls[0] = url;
        revert OffchainLookup(
            address(this),
            urls,
            callData,
            OffchainResolver.resolveWithProof.selector,
            msg.data
        );
    }

    /**
     * Callback used by CCIP read compatible clients to verify and parse the response.
     */
    function resolveWithProof(bytes calldata response, bytes calldata extraData) external view returns(bytes memory) {
       (address signer, bytes memory result) = SignatureVerifier.verify(
        extraData,response
       );
        require(signers[signer], "SignatureVerifier: Invalid sigature");
        return result;
    }

    function supportsInterface(bytes4 interfaceID) public pure override returns(bool) {
        return interfaceID == type(IExtendedResolver).interfaceId || super.supportsInterface(interfaceID);
    }

    // Helper function to convert hex string to bytes
    function hexStringToBytes(string memory s) internal pure returns (bytes memory) {
        bytes memory ss = bytes(s);
        require(ss.length % 2 == 0, "Invalid hex string length");
        bytes memory result = new bytes(ss.length / 2);
        for (uint256 i = 0; i < ss.length / 2; ++i) {
            result[i] = bytes1(
                fromHexChar(uint8(ss[2 * i])) * 16 + fromHexChar(uint8(ss[2 * i + 1]))
            );
        }
        return result;
    }

    function fromHexChar(uint8 c) internal pure returns (uint8) {
        if (bytes1(c) >= "0" && bytes1(c) <= "9") {
            return c - uint8(bytes1("0"));
        } else if (bytes1(c) >= "a" && bytes1(c) <= "f") {
            return 10 + c - uint8(bytes1("a"));
        } else if (bytes1(c) >= "A" && bytes1(c) <= "F") {
            return 10 + c - uint8(bytes1("A"));
        } else {
            revert("Invalid hex character");
        }
    }
}