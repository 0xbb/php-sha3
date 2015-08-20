<?php

namespace bb\Sha3;

class Sha3
{
    const KECCAK_ROUNDS = 24;
    
    private static function swapEndianness($hex)
    {
        return implode('', array_reverse(str_split($hex, 2)));
    }

    private static function  keccakf(&$st, $rounds)
    {
        $keccakf_rndc = [
            [0x00000000, 0x00000001], [0x00000000, 0x00008082], [0x80000000, 0x0000808a], [0x80000000, 0x80008000],
            [0x00000000, 0x0000808b], [0x00000000, 0x80000001], [0x80000000, 0x80008081], [0x80000000, 0x00008009],
            [0x00000000, 0x0000008a], [0x00000000, 0x00000088], [0x00000000, 0x80008009], [0x00000000, 0x8000000a],
            [0x00000000, 0x8000808b], [0x80000000, 0x0000008b], [0x80000000, 0x00008089], [0x80000000, 0x00008003],
            [0x80000000, 0x00008002], [0x80000000, 0x00000080], [0x00000000, 0x0000800a], [0x80000000, 0x8000000a],
            [0x80000000, 0x80008081], [0x80000000, 0x00008080], [0x00000000, 0x80000001], [0x80000000, 0x80008008]
        ];

        $keccakf_rotc = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
        $keccakf_piln = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12,2, 20, 14, 22, 9, 6, 1];


        $bc = [];
        for ($round = 0; $round < $rounds; $round++) {

            // Theta
            for ($i = 0; $i < 5; $i++) {
                $bc[$i] = [
                    $st[$i][0] ^ $st[$i + 5][0] ^ $st[$i + 10][0] ^ $st[$i + 15][0] ^ $st[$i + 20][0],
                    $st[$i][1] ^ $st[$i + 5][1] ^ $st[$i + 10][1] ^ $st[$i + 15][1] ^ $st[$i + 20][1]
                ];
            }

            for ($i = 0; $i < 5; $i++) {
                $t = [
                    $bc[($i + 4) % 5][0] ^ (($bc[($i + 1) % 5][0] << 1) | ($bc[($i + 1) % 5][1] >> 31)) & (0xFFFFFFFF),
                    $bc[($i + 4) % 5][1] ^ (($bc[($i + 1) % 5][1] << 1) | ($bc[($i + 1) % 5][0] >> 31)) & (0xFFFFFFFF)
                ];

                for ($j = 0; $j < 25; $j += 5) {
                    $st[$j + $i] = [
                        $st[$j + $i][0] ^ $t[0],
                        $st[$j + $i][1] ^ $t[1]
                    ];
                }
            }

            // Rho Pi
            $t = $st[1];
            for ($i = 0; $i < 24; $i++) {
                $j = $keccakf_piln[$i];

                $bc[0] = $st[$j];

                $n = $keccakf_rotc[$i];
                $hi = $t[0];
                $lo = $t[1];
                if ($n >= 32) {
                    $n -= 32;
                    $hi = $t[1];
                    $lo = $t[0];
                }

                $st[$j] =[
                    (($hi << $n) | ($lo >> (32 - $n))) & (0xFFFFFFFF),
                    (($lo << $n) | ($hi >> (32 - $n))) & (0xFFFFFFFF)
                ];


                $t = $bc[0];
            }

            //  Chi
            for ($j = 0; $j < 25; $j += 5) {
                for ($i = 0; $i < 5; $i++) {
                    $bc[$i] = $st[$j + $i];
                }
                for ($i = 0; $i < 5; $i++) {
                    $st[$j + $i] = [
                        $st[$j + $i][0] ^ ~$bc[($i + 1) % 5][0] & $bc[($i + 2) % 5][0],
                        $st[$j + $i][1] ^ ~$bc[($i + 1) % 5][1] & $bc[($i + 2) % 5][1]
                    ];
                }
            }

            // Iota
            $st[0] = [
                $st[0][0] ^ $keccakf_rndc[$round][0],
                $st[0][1] ^ $keccakf_rndc[$round][1]
            ];
        }
    }

    private static function keccak($in_raw, $capacity, $outputlength, $suffix, $raw_output)
    {
        $capacity /= 8;

        $inlen = strlen($in_raw);

        $rsiz = 200 - 2 * $capacity;
        $rsizw = $rsiz / 8;

        $st = [];
        for ($i = 0; $i < 25; $i++) {
            $st[] = [0, 0];
        }

        for ($in_t = 0; $inlen >= $rsiz; $inlen -= $rsiz, $in_t += $rsiz) {
            for ($i = 0; $i < $rsizw; $i++) {
                $t = unpack('V*', substr($in_raw, $i * 8 + $in_t, 8));

                $st[$i] = [
                    $st[$i][0] ^ $t[2],
                    $st[$i][1] ^ $t[1]
                ];
            }

            Sha3::keccakf($st, Sha3::KECCAK_ROUNDS);
        }

        $temp = substr($in_raw, $in_t, $inlen);
        $temp = str_pad($temp, $rsiz, "\x0", STR_PAD_RIGHT);

        $temp[$inlen] = chr($suffix);
        $temp[$rsiz - 1] = chr($temp[$rsiz - 1] | 0x80);

        for ($i = 0; $i < $rsizw; $i++) {
            $t = (unpack('V*', substr($temp, $i * 8, 8)));

            $st[$i] = [
                $st[$i][0] ^ $t[2],
                $st[$i][1] ^ $t[1]
            ];
        }

        Sha3::keccakf($st, Sha3::KECCAK_ROUNDS);

        $out = '';
        for ($i = 0; $i < 25; $i++) {
            $out .= Sha3::swapEndianness(sprintf("%08x%08x", $st[$i][0], $st[$i][1]));
        }
        $r = substr($out, 0, $outputlength / 4);

        return $raw_output ? hex2bin($r): $r;
    }

    public static function hash($in, $mdlen, $raw_output = false)
    {
        return Sha3::keccak($in, $mdlen, $mdlen, 0x06, $raw_output);
    }

    public static function shake($in, $mdlen, $outlen, $raw_outptut = false)
    {
        return Sha3::keccak($in, $mdlen, $outlen, 0x1f, $raw_outptut);
    }
}
