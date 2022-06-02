# Easy-ECC

[![Build Status](https://github.com/paragonie/easy-ecc/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/easy-ecc/actions)
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

// Signing a message (with PEM-formatted signatures):
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

#### NIST P521 + SHA521

```php
<?php
use ParagonIE\EasyECC\EasyECC;

$ecc = new EasyECC('P521');
```

### ECDSA-Specific Features

```php
<?php
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\{PublicKey, SecretKey};

// Generate an instance
$ecc = new EasyECC('P256');

// Get a keypair
/** @var SecretKey $alice_sk */
$alice_sk = $ecc->generatePrivateKey();
/** @var PublicKey $alice_pk */
$alice_pk = $alice_sk->getPublicKey();

// Serialize as PEM (for OpenSSL compatibility):
$alice_sk_pem = $alice_sk->exportPem();
$alice_pk_pem = $alice_pk->exportPem();

// Serialize public key as compressed point (for brevity):
$alice_pk_cpt = $alice_pk->toString();

$message = 'This is extremely simple to use correctly.';
// Signing a message (with IEEE-P1363-formatted signatures):
$signature = $ecc->sign($message, $alice_sk, true);
if (!$ecc->verify($message, $alice_pk, $signature, true)) {
    throw new Exception('Signature validation failed');
}

// Let's do a key exchange:
$bob_sk = $ecc->generatePrivateKey();
$bob_pk = $alice_sk->getPublicKey();

$alice_to_bob = $ecc->keyExchange($alice_sk, $bob_pk, true);
$bob_to_alice = $ecc->keyExchange($bob_sk, $alice_pk, false);
```

### Asymmetric Encryption

We provide an interface that you can implement for the underlying symmetric
cryptography to suit your needs. This library provides a built-in integration
for [Defuse's PHP encryption library](https://github.com/defuse/php-encryption).

```php
<?php
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\Integration\Defuse;
use Mdanter\Ecc\Crypto\Key\{
    PublicKeyInterface,
    PrivateKeyInterface
};

/**
 * @var EasyECC $ecc
 * @var PrivateKeyInterface $secretKey
 * @var PublicKeyInterface $publicKey
 */

// Let's load the integration (inject your EasyECC instance):
$defuse = new Defuse($ecc);

// You can seal/unseal messages (anonymous public-key encryption):
$superSecret = 'This is a secret message';
$sealed = $defuse->seal($superSecret, $publicKey);
$opened = $defuse->unseal($sealed, $secretKey);

// Or you can encrypt between two keypairs:
$otherSecret = $ecc->generatePrivateKey();
$otherPublic = $otherSecret->getPublicKey();
$encrypted = $defuse->asymmetricEncrypt($superSecret, $secretKey, $otherPublic);
$decrypted = $defuse->asymmetricDecrypt($encrypted, $otherSecret, $publicKey);
```

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
