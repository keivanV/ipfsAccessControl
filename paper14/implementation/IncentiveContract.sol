// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IncentiveContract {
    mapping(address => mapping(string => uint256)) public pool;
    mapping(string => uint256) public expects;
    mapping(string => address) public owners;

    event ExpectSet(string GID, uint256 value, address owner);
    event Deposited(string GID, address user, uint256 value);
    event Withdrawn(string GID, address user, uint256 value);
    event Rewarded(string GID, address user, address owner, address[] authorities);

    function expect(string memory GID, uint256 ownerVal) public {
        expects[GID] = ownerVal;
        owners[GID] = msg.sender;
        emit ExpectSet(GID, ownerVal, msg.sender);
    }

    function deposit(string memory GID) public payable {
        pool[msg.sender][GID] = msg.value;
        emit Deposited(GID, msg.sender, msg.value);
    }

    function withdraw(string memory GID) public {
        require(pool[msg.sender][GID] > 0, "No funds to withdraw");
        uint256 amount = pool[msg.sender][GID];
        pool[msg.sender][GID] = 0;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(GID, msg.sender, amount);
    }

    function reward(address user, address owner, address[] memory authorities, string memory GID) public {
        require(pool[user][GID] > expects[GID], "Insufficient deposit");
        uint256 ownerVal = expects[GID];
        uint256 remaining = pool[user][GID] - ownerVal;
        uint256 avg = remaining / authorities.length;
        pool[user][GID] = 0;
        payable(owner).transfer(ownerVal);
        for (uint i = 0; i < authorities.length; i++) {
            payable(authorities[i]).transfer(avg);
        }
        emit Rewarded(GID, user, owner, authorities);
    }
}