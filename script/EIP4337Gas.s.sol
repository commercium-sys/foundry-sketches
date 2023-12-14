// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { UserOperation, UserOperationLib } from "../src/libs/UserOperation.sol";
import { DepositPaymaster } from "../src/DepositPaymaster.sol";
import { VerifyingPaymaster } from "../src/VerifyingPaymaster.sol";
import { BaseAccount } from "../src/core/BaseAccount.sol";
import { Account } from "../src/Account.sol";
import { AccountFactory } from "../src/AccountFactory.sol";
import { IEntryPoint } from "../src/interfaces/IEntrypoint.sol";
import { IStakeManager } from "../src/interfaces/IStakeManager.sol";

import { EntryPoint } from "../src/core/EntryPoint.sol";
import { SenderCreator } from "../src/core/SenderCreator.sol";

contract AAScript is Script {

    function setUp() public {}

    function run() public {

        uint privk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable pubk = payable(vm.rememberKey(privk));

        vm.startBroadcast(pubk);

        IEntryPoint entrypoint = IEntryPoint(vm.envAddress("EIP_4337_ENTRYPOINT"));

        AccountFactory accountFactory = 
            AccountFactory(vm.envAddress("EIP_4337_ACCOUNT_FACTORY"));
            // new AccountFactory(address(entrypoint));

        address eip4337WalletAddr = accountFactory.getAddress(pubk, 1);

        // if (entrypoint.balanceOf(eip4337WalletAddr) == 0)
        //     entrypoint.depositTo{value: .05 ether}(eip4337WalletAddr);

        UserOperation memory userOp = UserOperation({
            sender: eip4337WalletAddr,
            nonce: 0,
            initCode: abi.encodePacked(
                address(accountFactory),
                abi.encodeWithSelector(
                    AccountFactory.createAccount.selector,
                    pubk,
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
            VerifyingPaymaster(payable(vm.envAddress("EIP_4337_VERIFYING_PAYMASTER")));

        // VerifyingPaymaster verifyingPaymaster = new VerifyingPaymaster(
        //     address(entrypoint),
        //     pubk
        // );

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            verifyingPaymaster.getHash(
                userOp,
                uint48(block.timestamp + 200000),
                uint48(block.timestamp)
            )
        );

        ( uint8 v, bytes32 r, bytes32 s ) = vm.sign(privk, digest);

        userOp.paymasterAndData = abi.encodePacked(
            address(verifyingPaymaster),
            abi.encode(
                uint48(block.timestamp + 200000),
                uint48(block.timestamp)
            ),
            bytes.concat(r,s,bytes1(v))
        );

        digest = MessageHashUtils.toEthSignedMessageHash(entrypoint.getUserOpHash(userOp));

        (v, r, s) = vm.sign(privk, digest);
        userOp.signature = bytes.concat(r, s, bytes1(v));

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        verifyingPaymaster.addStake{value: .05 ether}(84600);

        verifyingPaymaster.deposit{value: .05 ether}();

        entrypoint.handleOps(ops, pubk);

    }
}

contract Sim is Script {
    function run () public {

        EntryPoint replacement = new EntryPoint();

        address eip4337Entry = vm.envAddress("EIP_4337_ENTRYPOINT");

        vm.etch(eip4337Entry, address(replacement).code);

        eip4337Entry.call(vm.envBytes("PAYLOAD"));

    }
}

contract Withdraw is Script {
    function run () public {

        VerifyingPaymaster vp = VerifyingPaymaster(payable(vm.envAddress("EIP_4337_VERIFYING_PAYMASTER")));
        EntryPoint ep = EntryPoint(payable(vm.envAddress("EIP_4337_ENTRYPOINT")));

        uint privk = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address payable pubk = payable(vm.rememberKey(privk));

        EntryPoint.DepositInfo memory info = ep.getDepositInfo(address(vp));

        vm.broadcast(pubk);

        vp.withdrawTo(pubk, info.deposit);

    }
}

contract DepositIntoEntrypointForPaymaster is Script {

    function run () public {

        uint privk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable pubk  = payable(vm.rememberKey(privk));

        IEntryPoint entrypoint = IEntryPoint(vm.envAddress("AA_ENTRYPOINT"));

        address verifyingPaymaster = vm.envAddress("AA_VERIFYING_PAYMASTER");

        vm.startBroadcast(pubk);

        entrypoint.depositTo{value: .5 ether}(address(verifyingPaymaster));

    }

}

contract DeployVerifyingPaymaster is Script {

    function run () public {

        uint privk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable pubk  = payable(vm.rememberKey(privk));

        IEntryPoint entrypoint = IEntryPoint(vm.envAddress("AA_ENTRYPOINT"));

        vm.startBroadcast(pubk);

        VerifyingPaymaster verifyingPaymaster = new VerifyingPaymaster(
            address(entrypoint),
            pubk
        );

        vm.stopBroadcast();

    }
}