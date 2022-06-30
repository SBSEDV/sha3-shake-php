<?php declare(strict_types=1);

namespace SBSEDV\SHA3Shake\Tests;

use PHPUnit\Framework\TestCase;
use SBSEDV\SHA3Shake\SHA3;

class SHA3Test extends TestCase
{
    public function testShake(): void
    {
        $testCases = [
            128 => [
                // output_length, raw_input, expected_output
                [256, '', '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'],
                [256, 'This is a SHAKE128 test string.', '88a5aca15e54e1724fd6e191b4694c742eeba3d2433da71188a21dec93a064ed'],
                [256, 'This is another SHAKE128 test string.', '95a2e0aa878aed2edafee2edc5a9493f39b82a6273fbd5cd820412cf33eb38b0'],
            ],
            256 => [
                [512, '', '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'],
                [512, 'This is a SHAKE256 test string.', '3477218c282909fa2e1df2e7c3bc4e6bb2c935ceaf95c4b421bfb948bcc750b8e7da8f04d85f8bfaf80f5b09c007fd7d43aa0361da1cb79b875d32114b1f9421'],
                [512, 'This is another SHAKE256 test string.', '1296397e3b6747173f437148309a4309477887e152521e41b6eaa7a160ce890de12ac6153d545c8ace82c84e1ccf9a3813357cdaf3fd4f31ca5bfc2354945084'],
            ],
        ];

        foreach ($testCases as $capacity => $x) {
            foreach ($x as $testcase) {
                $this->assertEquals(SHA3::shake($testcase[1], $capacity, $testcase[0]), $testcase[2]);

                $this->assertEquals(SHA3::shake($testcase[1], $capacity, $testcase[0], true), \hex2bin($testcase[2]));
            }
        }
    }

    /**
     * Test that only "128" and "256" is accepted as capacity.
     */
    public function testShakeCapacity(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SHA3::shake('', 999, 256);
    }
}
