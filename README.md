# Easy-ECC

[![Build Status](https://travis-ci.org/paragonie/easy-ecc.svg?branch=master)](https://travis-ci.org/paragonie/easy-ecc)
[![Latest Stable Version](https://poser.pugx.org/paragonie/easy-ecc/v/stable)](https://packagist.org/packages/paragonie/easy-ecc)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/easy-ecc/v/unstable)](https://packagist.org/packages/paragonie/easy-ecc)
[![License](https://poser.pugx.org/paragonie/easy-ecc/license)](https://packagist.org/packages/paragonie/easy-ecc)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/easy-ecc.svg)](https://packagist.org/packages/paragonie/easy-ecc)

A usability wrapper for [PHP ECC](https://github.com/phpecc/phpecc).

## Installing

```
composer require paragonie/easy-ecc
```

## Using Easy-ECC

```php
<?php
use ParagonIE\EasyECC\EasyECC;

// Generate an instance; defaults to Curve25519
$ecc = new EasyECC();

// Get a keypair
$alice_sk = $ecc->generatePrivateKey();
$alice_pk = $alice_sk->getPublicKey();

// Signing a message:
$message = 'This is extremely simple to use correctly.';
$signature = $ecc->sign($message, $alice_sk);

if (!$ecc->verify($message, $alice_pk, $signature)) {
    throw new Exception('Signature validation failed');
}

// Let's do a key exchange:
$bob_sk = $ecc->generatePrivateKey();
$bob_pk = $alice_sk->getPublicKey();

$alice_to_bob = $ecc->keyExchange($alice_sk, $bob_pk, true);
$bob_to_alice = $ecc->keyExchange($bob_sk, $alice_pk, false);
```

### Other Easy-ECC Modes

#### secp256k1 + SHA256

```php
<?php
use ParagonIE\EasyECC\EasyECC;

$ecc = new EasyECC('K256');
```

#### NIST P256 + SHA256

```php
<?php
use ParagonIE\EasyECC\EasyECC;

$ecc = new EasyECC('P256');
```

#### NIST P384 + SHA384

```php
<?php
use ParagonIE\EasyECC\EasyECC;

$ecc = new EasyECC('P384');
```
