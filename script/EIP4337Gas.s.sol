// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { UserOperation, UserOperationLib } from "../src/eip4337Script/libs/UserOperation.sol";
import { DepositPaymaster } from "../src/eip4337Script/DepositPaymaster.sol";
import { VerifyingPaymaster } from "../src/eip4337Script/VerifyingPaymaster.sol";
import { BaseAccount } from "../src/eip4337Script/core/BaseAccount.sol";
import { Account } from "../src/eip4337Script/Account.sol";
import { AccountFactory } from "../src/eip4337Script/AccountFactory.sol";
import { IEntryPoint } from "../src/eip4337Script/interfaces/IEntrypoint.sol";
import { IStakeManager } from "../src/eip4337Script/interfaces/IStakeManager.sol";

import { EntryPoint } from "../src/eip4337Script/core/EntryPoint.sol";
import { SenderCreator } from "../src/eip4337Script/core/SenderCreator.sol";

import { VmSafe } from "forge-std/Vm.sol";


contract AAScript is Script {

    function setUp() public {}

    function run() public {

        VmSafe.Wallet memory wallet = vm.createWallet("wallet");

        vm.deal(wallet.addr, 100 ether);

        vm.startBroadcast(wallet.addr);

        IEntryPoint entrypoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);

        AccountFactory accountFactory = AccountFactory(0xb1d4bDDc41d51057587bdF373ebcaf61c76f31c8);

        address eip4337WalletAddr = accountFactory.getAddress(wallet.addr, 1);

        UserOperation memory userOp = UserOperation({
            sender: eip4337WalletAddr,
            nonce: 0,
            initCode: abi.encodePacked(
                address(accountFactory),
                abi.encodeWithSelector(
                    AccountFactory.createAccount.selector,
                    wallet.addr,
                    1
                )
            ),
            callData: "",
            callGasLimit: 7000000,
            verificationGasLimit: 70000,
            preVerificationGas: 50000,
            maxFeePerGas: 1000000000,
            maxPriorityFeePerGas: 1000000000,
            paymasterAndData: "",
            signature: ""
        });

        VerifyingPaymaster verifyingPaymaster = 
            VerifyingPaymaster(payable(0x40CD4FFC9D4BfC82fdf5FB922d07bE8d0032299d));

        IEntryPoint.DepositInfo memory info = entrypoint.getDepositInfo(address(verifyingPaymaster));

        if (info.deposit == 0)
            verifyingPaymaster.deposit{value: .05 ether}();

        if (info.stake == 0)
            verifyingPaymaster.addStake{value: .05 ether}(84600);

        {
            bytes32 paymasterDigest = 
                MessageHashUtils.toEthSignedMessageHash(
                    verifyingPaymaster.getHash
                        (userOp, uint48(block.timestamp + 200000), uint48(block.timestamp)));

            ( uint8 v, bytes32 r, bytes32 s ) = vm.sign(wallet.privateKey, paymasterDigest);

            userOp.paymasterAndData = abi.encodePacked(
                address(verifyingPaymaster),
                abi.encode(uint48(block.timestamp + 200000), uint48(block.timestamp)),
                bytes.concat(r,s,bytes1(v))
            );
        }

        {
            bytes32 userOpDigest = 
                MessageHashUtils.toEthSignedMessageHash(entrypoint.getUserOpHash(userOp));

            ( uint8 v, bytes32 r, bytes32 s ) = vm.sign(wallet.privateKey, userOpDigest);

            userOp.signature = bytes.concat(r, s, bytes1(v));
        }

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        entrypoint.handleOps{gas: 200000}(ops, payable(wallet.addr));

    }
}