<?php declare(strict_types=1);

namespace danielburger1337\SHA3Shake;

final class SHA3Shake
{
    private const KECCAK_ROUNDS = 24;
    private const KECCAKF_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
    private const KECCAKF_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    private const KECCAKF_RNDC = [
        [0x00000000, 0x00000001], [0x00000000, 0x00008082], [0x80000000, 0x0000808A], [0x80000000, 0x80008000],
        [0x00000000, 0x0000808B], [0x00000000, 0x80000001], [0x80000000, 0x80008081], [0x80000000, 0x00008009],
        [0x00000000, 0x0000008A], [0x00000000, 0x00000088], [0x00000000, 0x80008009], [0x00000000, 0x8000000A],
        [0x00000000, 0x8000808B], [0x80000000, 0x0000008B], [0x80000000, 0x00008089], [0x80000000, 0x00008003],
        [0x80000000, 0x00008002], [0x80000000, 0x00000080], [0x00000000, 0x0000800A], [0x80000000, 0x8000000A],
        [0x80000000, 0x80008081], [0x80000000, 0x00008080], [0x00000000, 0x80000001], [0x80000000, 0x80008008],
    ];

    /**
     * Calculate the SHAKE-128 hash of a string.
     *
     * @param string $string       The input string.
     * @param int    $outputLength The length of the digest in bytes.
     * @param bool   $binary       [optional] If the optional raw_output is set to true,
     *                             then the digest is instead returned in raw binary format.
     */
    public static function shake128(string $string, int $outputLength, bool $binary = false): string
    {
        return self::doHash($string, 128, $outputLength, $binary);
    }

    /**
     * Calculate the SHAKE-256 hash of a string.
     *
     * @param string $string       The input string.
     * @param int    $outputLength The length of the digest in bytes.
     * @param bool   $binary       [optional] If the optional raw_output is set to true,
     *                             then the digest is instead returned in raw binary format.
     */
    public static function shake256(string $string, int $outputLength, bool $binary = false): string
    {
        return self::doHash($string, 256, $outputLength, $binary);
    }

    /**
     * @param string $string       The input string.
     * @param int    $capacity     The SHAKE algorithm capacity.
     * @param int    $outputLength The length of the digest.
     * @param bool   $binary       [optional] If the optional raw_output is set to true,
     *                             then the digest is instead returned in raw binary format.
     */
    private static function doHash(string $string, int $capacity, int $outputLength, bool $binary = false): string
    {
        if (\PHP_INT_SIZE !== 8) {
            throw new \RuntimeException('This SHA3-SHAKE implementation is only available for 64-bit PHP.');
        }

        if (!\in_array($capacity, [128, 256], true)) {
            throw new \InvalidArgumentException('Invalid capacity. Supported are 128 and 256');
        }

        if (($outputLength & 1) !== 0) {
            throw new \InvalidArgumentException('Invalid outputLength. Output length must be divisible by 2');
        }

        $capacity >>= 3;

        $inlen = \mb_strlen($string, '8bit');

        $rsiz = 200 - ($capacity << 1);
        $rsizw = $rsiz >> 3;

        $st = [];
        for ($i = 0; $i < 25; ++$i) {
            $st[] = [0, 0];
        }

        for ($in_t = 0; $inlen >= $rsiz; $inlen -= $rsiz, $in_t += $rsiz) {
            for ($i = 0; $i < $rsizw; ++$i) {
                $t = \unpack('V*', self::substr($string, $i * 8 + $in_t, 8));

                if (false === $t) {
                    throw new \RuntimeException('unpack() failed.');
                }

                $st[$i] = [
                    $st[$i][0] ^ $t[2],
                    $st[$i][1] ^ $t[1],
                ];
            }

            self::keccakf64($st);
        }

        $temp = self::substr($string, $in_t, $inlen);
        $temp = \str_pad($temp, $rsiz, "\x0", \STR_PAD_RIGHT);

        $temp[$inlen] = self::chr(0x1F);
        $temp[$rsiz - 1] = self::chr(self::ord($temp[$rsiz - 1]) | 0x80);

        for ($i = 0; $i < $rsizw; ++$i) {
            $t = \unpack('V*', self::substr($temp, $i << 3, 8));

            if (false === $t) {
                throw new \RuntimeException('unpack() failed.');
            }

            $st[$i] = [
                $st[$i][0] ^ $t[2],
                $st[$i][1] ^ $t[1],
            ];
        }

        self::keccakf64($st);

        $out = '';
        for ($i = 0; $i < 25; ++$i) {
            $out .= \pack('V*', $st[$i][1], $st[$i][0]);
        }
        $r = self::substr($out, 0, (int) ($outputLength >> 1));

        if (function_exists('sodium_bin2hex')) {
            return $binary ? $r : \sodium_bin2hex($r);
        }
        return $binary ? $r : \bin2hex($r);
    }

    /**
     * @param array<int, int[]> $st
     */
    private static function keccakf64(array &$st): void
    {
        $bc = [];
        for ($round = 0; $round < self::KECCAK_ROUNDS; ++$round) {
            // Theta
            for ($i = 0; $i < 5; ++$i) {
                $bc[$i] = [
                    $st[$i][0] ^ $st[$i + 5][0] ^ $st[$i + 10][0] ^ $st[$i + 15][0] ^ $st[$i + 20][0],
                    $st[$i][1] ^ $st[$i + 5][1] ^ $st[$i + 10][1] ^ $st[$i + 15][1] ^ $st[$i + 20][1],
                ];
            }

            for ($i = 0; $i < 5; ++$i) {
                $t = [
                    $bc[($i + 4) % 5][0] ^ (($bc[($i + 1) % 5][0] << 1) | ($bc[($i + 1) % 5][1] >> 31)) & 0xFFFFFFFF,
                    $bc[($i + 4) % 5][1] ^ (($bc[($i + 1) % 5][1] << 1) | ($bc[($i + 1) % 5][0] >> 31)) & 0xFFFFFFFF,
                ];

                for ($j = 0; $j < 25; $j += 5) {
                    $st[$j + $i] = [
                        $st[$j + $i][0] ^ $t[0],
                        $st[$j + $i][1] ^ $t[1],
                    ];
                }
            }

            // Rho Pi
            $t = $st[1];
            for ($i = 0; $i < 24; ++$i) {
                $j = self::KECCAKF_PILN[$i];

                $bc[0] = $st[$j];

                $n = self::KECCAKF_ROTC[$i];
                $hi = $t[0];
                $lo = $t[1];
                if ($n >= 32) {
                    $n -= 32;
                    $hi = $t[1];
                    $lo = $t[0];
                }

                $st[$j] = [
                    (($hi << $n) | ($lo >> (32 - $n))) & 0xFFFFFFFF,
                    (($lo << $n) | ($hi >> (32 - $n))) & 0xFFFFFFFF,
                ];

                $t = $bc[0];
            }

            //  Chi
            for ($j = 0; $j < 25; $j += 5) {
                for ($i = 0; $i < 5; ++$i) {
                    $bc[$i] = $st[$j + $i];
                }
                for ($i = 0; $i < 5; ++$i) {
                    $st[$j + $i] = [
                        $st[$j + $i][0] ^ ~$bc[($i + 1) % 5][0] & $bc[($i + 2) % 5][0],
                        $st[$j + $i][1] ^ ~$bc[($i + 1) % 5][1] & $bc[($i + 2) % 5][1],
                    ];
                }
            }

            // Iota
            $st[0] = [
                $st[0][0] ^ self::KECCAKF_RNDC[$round][0],
                $st[0][1] ^ self::KECCAKF_RNDC[$round][1],
            ];
        }
    }

    private static function chr(int $x): string
    {
        return \pack('C', $x);
    }

    private static function ord(string $c): int
    {
        $ord = \unpack('C', $c[0]);
        if (!\is_array($ord) || !array_key_exists(1, $ord)) {
            throw new \RuntimeException('Error decoding string to integer');
        }
        return (int) $ord[1];
    }

    /**
     * Shortcut for "mb_substr" with 8bit encoding.
     */
    private static function substr(string $string, int $start = 0, ?int $length = null): string
    {
        return \mb_substr($string, $start, $length, '8bit');
    }
}
