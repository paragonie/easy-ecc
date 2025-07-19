<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Curve25519;

use Mdanter\Ecc\Crypto\EcDH\EcDHInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class EdwardsSecretKey
 * @package ParagonIE\EasyECC\Curve25519
 */
final class EdwardsSecretKey implements PrivateKeyInterface
{
    /** @var string $secretKey */
    protected $secretKey;

    /**
     * EdwardsSecretKey constructor.
     *
     * @param string $keyMaterial
     * @throws \SodiumException
     */
    public function __construct(string $keyMaterial)
    {
        if (Binary::safeStrlen($keyMaterial) === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
            $this->secretKey = \sodium_crypto_sign_secretkey($keyMaterial);
        } else if (Binary::safeStrlen($keyMaterial) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            $this->secretKey = $keyMaterial;
        } else if (Binary::safeStrlen($keyMaterial) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $keypair = \sodium_crypto_sign_seed_keypair($keyMaterial);
            $this->secretKey = \sodium_crypto_sign_secretkey($keypair);
        } else {
            throw new \SodiumException('Invalid secret key provided');
        }
    }

    /**
     * @return string
     */
    public function getAsString(): string
    {
        return $this->secretKey;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        return $this->secretKey;
    }

    /**
     * @return MontgomerySecretKey
     * @throws \SodiumException
     */
    public function getMontgomery(): MontgomerySecretKey
    {
        return new MontgomerySecretKey(
            \sodium_crypto_sign_ed25519_sk_to_curve25519($this->secretKey)
        );
    }

    /**
     * @return PublicKeyInterface
     * @throws \SodiumException
     */
    public function getPublicKey(): PublicKeyInterface
    {
        return new EdwardsPublicKey(
            \sodium_crypto_sign_publickey_from_secretkey($this->secretKey)
        );
    }

    /**
     * @return GeneratorPoint
     * @throws NotImplementedException
     */
    public function getPoint(): GeneratorPoint
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * @return \GMP
     * @throws NotImplementedException
     */
    public function getSecret(): \GMP
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * @param PublicKeyInterface $recipient
     * @return EcDHInterface
     * @throws NotImplementedException
     */
    public function createExchange(PublicKeyInterface $recipient): EcDHInterface
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }
}
