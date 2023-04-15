[![PHPUnit](https://github.com/SBSEDV/sha3-shake-php/actions/workflows/phpunit.yml/badge.svg)](https://github.com/SBSEDV/sha3-shake-php/actions/workflows/phpunit.yml)

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

The library exposes two public static method for both shake versions.
See the PHPDoc annotation for more information about the arguments.

```php
<?php
    use SBSEDV\SHA3Shake\SHA3Shake;

    SHA3Shake::shake128('This is a test string.', 64);
    // 041b3634a7b103979e4c7e100cdc6ec19e3541b15633657ebae4bb7dd9aca0dc

    SHA3Shake::shake256('This is a test string.', 64);
    // ec31f7a681a317a276b844e22e3e777834c5de311816d70329d5c8054846946b
```

---

## **Sources**

This library uses a modified implementation from the abandoned [bb/php-sha3](https://github.com/0xbb/php-sha3) package.
