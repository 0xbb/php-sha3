<?php

namespace bb\Sha3\Test;

use PHPUnit_Framework_TestCase;
use bb\Sha3\Sha3;


class Sha3Test extends PHPUnit_Framework_TestCase
{

const short = "52A608AB21CCDD8A4457A57EDE782176";
const long = "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E085172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1";

    public function  testSha3()
    {
        $v = [
            512 => [
                ['','a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'],
                ['The quick brown fox jumps over the lazy dog', '01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450'],
                ['The quick brown fox jumps over the lazy dog.','18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8'],
                [hex2bin(Sha3Test::short), '001618372e75147af90c0cf16c3bbdaa069ddbc62483b392d028ded49f75084a5dfcc53aecd9f57ddbb73daa041fd71089d8fb5edf6cfaf6f1e4e25ad3de266c'],
                [hex2bin(Sha3Test::long), '6e8b8bd195bdd560689af2348bdc74ab7cd05ed8b9a57711e9be71e9726fda4591fee12205edacaf82ffbbaf16dff9e702a708862080166c2ff6ba379bc7ffc2']
            ],
            384 => [
                ['', '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'],
                ['The quick brown fox jumps over the lazy dog', '7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41'],
                ['The quick brown fox jumps over the lazy dog.', '1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9'],
                [hex2bin(Sha3Test::short), 'feee2ef332515284e0ba247c62f264199044d03877c58e54b51a62e39e91c27aaae384837eb9d479b4c0308cfc6b779b'],
                [hex2bin(Sha3Test::long), '128dc611762be9b135b3739484cfaadca7481d68514f3dfd6f5d78bb1863ae68130835cdc7061a7ed964b32f1db75ee1'],
                [hex2bin('E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826DB923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A21691E1069413848'), 'd1c0fa85c8d183beff99ad9d752b263e286b477f79f0710b010317017397813344b99daf3bb7b1bc5e8d722bac85943a'],
            ],
            256 => [
                ['', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'],
                ['The quick brown fox jumps over the lazy dog', '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04'],
                ['The quick brown fox jumps over the lazy dog.', 'a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d'],
                [hex2bin(Sha3Test::short), '2c7e7cb356fdc68ec8927e499d2a6bae2b781817919c829ebbe8225baed46967'],
                [hex2bin(Sha3Test::long), 'c11f3522a8fb7b3532d80b6d40023a92b489addad93bf5d64b23f35e9663521c'],
                [hex2bin('9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10'), '2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af'],
            ],
            224 => [
                ['', '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'],
                ['The quick brown fox jumps over the lazy dog', 'd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795'],
                ['The quick brown fox jumps over the lazy dog.', '2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0'],
                [hex2bin(Sha3Test::short), 'b1571bed52e54eef377d99df7be4bc6682c43387f2bf9acc92df608f'],
                [hex2bin(Sha3Test::long), '94689ea9f347dda8dd798a858605868743c6bd03a6a65c6085d52bed'],
             ],

        ];

        foreach($v as $bitsize => $vectors){
            foreach($vectors as $testcase){
                $this->assertEquals(Sha3::hash($testcase[0], $bitsize), $testcase[1]);
            }
        }
    }

    public function  testShake()
    {
        $v = [
            128 => [
                [256, '', '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'],
                [256, hex2bin(Sha3Test::short), '3a0faca70c9d2b81d1064d429ea3b05ad27366f64985379ddd75bc73d6a83810'],
                [256, hex2bin(Sha3Test::long), '14236e75b9784df4f57935f945356cbe383fe513ed30286f91060759bcb0ef4b'],
                [256, 'The quick brown fox jumps over the lazy dog', 'f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e'],
                [256, 'The quick brown fox jumps over the lazy dof', '853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c'],
            ],
            256 => [
                [512, '', '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'],
                [512, hex2bin(Sha3Test::short), '57119c4507f975ad0e9ea4f1166e5f9b590bf2671aaeb41d130d2c570bafc579b0b9ec485cc736a0a848bbc886cbaa79ffcd067ce64b3b410741ab011c544225'],
                [512, hex2bin(Sha3Test::long), '8a5199b4a7e133e264a86202720655894d48cff344a928cf8347f48379cef347dfc5bcffab99b27b1f89aa2735e23d30088ffa03b9edb02b9635470ab9f10389'],
            ]
        ];

        foreach($v as $bitsize => $vectors){
            foreach($vectors as $testcase){
                $this->assertEquals(Sha3::shake($testcase[1], $bitsize, $testcase[0]), $testcase[2]);
            }
        }
    }
}