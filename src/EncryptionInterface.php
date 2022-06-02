<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;

interface EncryptionInterface
{
    public function __construct(EasyECC $ecc);

    public function asymmetricEncrypt(
        string $message,
        PrivateKeyInterface $privateKey,
        PublicKeyInterface $publicKey
    ): string;

    public function asymmetricDecrypt(
        string $message,
        PrivateKeyInterface $privateKey,
        PublicKeyInterface $publicKey
    ): string;

    public function seal(
        string $message,
        PublicKeyInterface $publicKey
    ): string;

    public function unseal(
        string $message,
        PrivateKeyInterface $privateKey
    ): string;
}
