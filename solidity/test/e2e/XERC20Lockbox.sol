// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4 <0.9.0;

import {CommonE2EBase} from './Common.sol';
import {PermitHash} from 'libraries/PermitHash.sol';
// import {IAllowanceTransfer} from 'interfaces/IAllowanceTransfer.sol';
import {ISignatureTransfer} from 'interfaces/ISignatureTransfer.sol';
import {PermitSignature} from 'libraries/PermitSignature.sol';
import {IEIP712} from 'interfaces/IEIP712.sol';
import {XERC20Lockbox} from 'contracts/XERC20Lockbox.sol';
import {XERC20} from 'contracts/XERC20.sol';

contract E2ELockbox is CommonE2EBase, PermitSignature {
  // function sign(bytes32 msgHash, uint256 privateKey) public pure returns (bytes memory sig) {
  //   (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
  //   return bytes.concat(r, s, bytes1(v));
  // }

  function testLockbox() public {
    assertEq(address(_lockbox.XERC20()), address(_xerc20));
    assertEq(address(_lockbox.ERC20()), address(_dai));
  }

  function testDeposit() public {
    deal(address(_dai), _user, 100 ether);
    vm.startPrank(_user);
    _dai.approve(address(_lockbox), 100 ether);
    _lockbox.deposit(100 ether);
    vm.stopPrank();

    assertEq(XERC20(_xerc20).balanceOf(_user), 100 ether);
    assertEq(_dai.balanceOf(_user), 0 ether);
  }

  function testDepositWithPermit() public {
    uint256 _amount = 100 ether;
    uint256 _expiration = 10_000_000_000_000;

    deal(address(_dai), _user, _amount);
    vm.startPrank(_user);
    _dai.approve(address(_lockbox), _amount);

    // ISignatureTransfer.SignatureTransferDetails memory details =
    //   ISignatureTransfer.SignatureTransferDetails({to: address(_spender), requestedAmount: _amount});

    ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
      permitted: ISignatureTransfer.TokenPermissions({token: address(_dai), amount: _amount}),
      nonce: 0,
      deadline: _expiration
    });

    // bytes32 domainSeparator = ISignatureTransfer(_lockbox.PERMIT2.address).DOMAIN_SEPARATOR();
    bytes memory signature =
      getPermitTransferSignature(permit, _userPrivateKey, 0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28);

    _lockbox.depositWithPermitTransferFrom(_amount, _user, permit, signature);
    vm.stopPrank();

    assertEq(XERC20(_xerc20).balanceOf(_user), _amount);
    assertEq(_dai.balanceOf(_user), 0 ether);
  }

  // function testDepositWithPermit() public {
  //   deal(address(_dai), _user, 100 ether);
  //   vm.startPrank(_user);
  //   _dai.approve(address(_lockbox), 100 ether);

  //   // Generate signature
  //   bytes32 msgHash = PermitHash._PERMIT_SINGLE_TYPEHASH;
  //   uint256 amountToDeposit = 100 ether;

  //   IAllowanceTransfer.PermitSingle memory permit = IAllowanceTransfer.PermitSingle({
  //     details: IAllowanceTransfer.PermitDetails({
  //       token: address(_dai),
  //       amount: uint160(amountToDeposit),
  //       expiration: 10000000000000,
  //       nonce: 0
  //     }),
  //     spender: address(_dai),
  //     sigDeadline: 10000000000000
  //   });

  //   bytes memory signature = sign(keccak256(abi.encode(msgHash, permit.details, permit.spender, permit.sigDeadline)), _userPrivateKey);

  //   _lockbox.depositWithPermit(amountToDeposit, permit, signature);
  //   vm.stopPrank();

  //   assertEq(XERC20(_xerc20).balanceOf(_user), 100 ether);
  //   assertEq(_dai.balanceOf(_user), 0 ether);
  // }

  function testWithdraw() public {
    deal(address(_dai), _user, 100 ether);
    vm.startPrank(_user);
    _dai.approve(address(_lockbox), 100 ether);
    _lockbox.deposit(100 ether);
    vm.stopPrank();

    vm.startPrank(_user);
    _lockbox.withdraw(100 ether);
    vm.stopPrank();

    assertEq(XERC20(_xerc20).balanceOf(_user), 0 ether);
    assertEq(_dai.balanceOf(_user), 100 ether);
  }
}
