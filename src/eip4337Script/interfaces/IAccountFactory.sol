// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;
import "./IAccount.sol";

interface AccountFactory {

    function createAccount(address owner,uint256 salt) external returns (IAccount);
    function getAddress(address owner, uint256 salt) external view returns (address);

}