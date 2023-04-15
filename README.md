# SHA3-SHAKE

Native PHP implementation of the SHA3-SHAKE (KECCAK) algorithm.

This library is [PSR-4](https://www.php-fig.org/psr/psr-4/) compatible and can be installed via PHP's dependency manager [Composer](https://getcomposer.org).

```shell
composer require sbsedv/sha3-shake
```

This library requires a 64-bit version of PHP.

---

## **Why does this library exist ?**

Since version ^7.1 the SHA3 algorithm is nativly supported by PHP via the [`hash`](https://www.php.net/manual/function.hash) function. However, the SHAKE128 and SHAKE256 variants are not supported.

---

## **How To Use**

The library exposes only one public static method.
See the PHPDoc annotation for more information about the arguments.

```php
<?php
    use SBSEDV\SHA3Shake\SHA3;

    SHA3::shake('This is a This is a SHAKE128 test string.', 128, 256);
    // 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26

    SHA3::shake('This is a SHAKE256 test string.', 256, 512);
    // 3477218c282909fa2e1df2e7c3bc4e6bb2c935ceaf95c4b421bfb948bcc750b8e7da8f04d85f8bfaf80f5b09c007fd7d43aa0361da1cb79b875d32114b1f9421
```

---

## **Sources**

This library uses a modified implementation from the abandoned [bb/php-sha3](https://github.com/0xbb/php-sha3) package.
