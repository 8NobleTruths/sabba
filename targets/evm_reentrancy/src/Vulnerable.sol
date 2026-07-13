// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A classic reentrancy: the external call happens before the balance is zeroed, so a
// receiver that calls back into withdraw drains the vault. Self-contained on purpose, so
// the exploit deploys and drains it on a local EVM with no fork needed.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0; // effect after interaction: the bug
    }

    receive() external payable {}
}
