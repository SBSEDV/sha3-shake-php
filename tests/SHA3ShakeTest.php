<?php declare(strict_types=1);

namespace danielburger1337\SHA3Shake\Tests;

use danielburger1337\SHA3Shake\SHA3Shake;
use PHPUnit\Framework\TestCase;

class SHA3Test extends TestCase
{
    /**
     * Test that only even output lengths are accepted.
     */
    public function testShakeOutputLength(): void
    {
        SHA3Shake::shake128('', 256);
        SHA3Shake::shake256('', 128);

        $this->expectException(\InvalidArgumentException::class);
        SHA3Shake::shake128('', 63);

        $this->expectException(\InvalidArgumentException::class);
        SHA3Shake::shake256('', 57);
    }

    /**
     * @dataProvider shake128Provider
     */
    public function testShake128(string $string, int $outputLength, string $expected): void
    {
        $hash = SHA3Shake::shake128($string, $outputLength, false);
        $this->assertEquals($hash, $expected);

        $this->assertTrue(\mb_strlen($hash, '8bit') === $outputLength);

        $this->assertEquals(SHA3Shake::shake128($string, $outputLength, true), \hex2bin($expected));
    }

    /**
     * @dataProvider shake256Provider
     */
    public function testShake256(string $string, int $outputLength, string $expected): void
    {
        $hash = SHA3Shake::shake256($string, $outputLength, false);
        $this->assertEquals($hash, $expected);

        $this->assertTrue(\mb_strlen($hash, '8bit') === $outputLength);

        $this->assertEquals(SHA3Shake::shake256($string, $outputLength, true), \hex2bin($expected));
    }

    protected function shake128Provider(): array
    {
        return [
            [
                '', 64, '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
            ],
            [
                'This is a test string.', 256, '041b3634a7b103979e4c7e100cdc6ec19e3541b15633657ebae4bb7dd9aca0dc3a0ffe4a202f9fadad9ce141b9861f384fb451ffb1fd79396592f14ffbacc1f83a2b8997fd1ab7c91ee16821756f31b8997b6db1f398d9fbb3b5879908b691957439ca7e009a38ba3de4970ea206182d991d9afc8f8d53fc307ace22d60673e5',
            ],
        ];
    }

    protected function shake256Provider(): array
    {
        return [
            [
                // @see https://bitbucket.org/openid/connect/issues/1125
                'YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL',
                114,
                'b01fd4ef68f26f45a0b57f13b15a2a2679ba083dbde56f607d20d1c648a50772c02fb4448bd258bad456fecd72138943f1c39f3197fcde08b8',
            ],
            [
                '', 64, '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
            ],
            [
                'This is a test string.', 256, 'ec31f7a681a317a276b844e22e3e777834c5de311816d70329d5c8054846946bf087163bb91c722a221caa336fd187cdc21b4718995cf729706d92d706d0ff8537f7ddea6271c4549451a17f9a133be23a403f2d6447babcb9b21da4f1d2bc5a4c51a12bfe96aa29560d47f545083d1438cbf7034f5dc1e92e9068980969b01b',
            ],
        ];
    }
}
