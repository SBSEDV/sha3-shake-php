<?php declare(strict_types=1);

use danielburger1337\SHA3Shake\SHA3Shake;

require 'src/SHA3Shake.php';

$hash = SHA3Shake::shake256('This is a test string.', 64);

echo $hash.PHP_EOL;
