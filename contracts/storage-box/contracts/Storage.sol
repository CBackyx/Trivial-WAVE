// SPDX-License-Identifier: MIT
pragma solidity 0.5.16;

contract Storage {
    mapping (bytes => bytes[]) cert_st;
    // Entity name + Url name > Cert

    mapping (bytes => Keys) key_st;
    // Entity name > Keys

    mapping (bytes => bytes) revoke_st;

    // The mapping from entity name to address is omitted

    struct Keys {
        bool non_empty;
        bytes sign_pubKey;
        bytes attest_pubKey;
    }

    // event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor() public {
    }

    function newEntity(bytes memory name, bytes memory spubk, bytes memory apubk) public returns(bool) {
        // if(key_st[name].non_empty) revert('Entity existed!');
        key_st[name] = Keys(true, spubk, apubk);
        return true;
    }

    function getEntitySignPubKey(bytes memory name) public view returns(bytes memory){
        return key_st[name].sign_pubKey;
    }

    function getEntitySignStatus(bytes memory name) public view returns(bool){
        return key_st[name].non_empty;
    }

    function getEntityAttestPubKey(bytes memory name) public view returns(bytes memory){
        return key_st[name].attest_pubKey;
    }

    function uploadCert(bytes memory id, bytes memory cert) public {
        cert_st[id].push(cert);
    }

    function putRevokeSign(bytes memory certSign, bytes memory revokeSign) public {
        revoke_st[certSign] = revokeSign;
    }

    function getRevokeSign(bytes memory certSign) public view returns(bytes memory) {
        return revoke_st[certSign];
    }

    function getCertNum(bytes memory id) public view returns(uint){
        return cert_st[id].length;
    }

    function getCert(bytes memory id, uint index) public view returns(bytes memory){
        if (cert_st[id].length == 0)
            return new bytes(0);
        return cert_st[id][index];
    }

    function testGet(uint index) public pure returns(string memory){
        return "hello";
    }
}
