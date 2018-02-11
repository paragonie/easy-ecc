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
 * Class MontgomerySecretKey
 * @package ParagonIE\EasyECC\Curve25519
 */
class MontgomerySecretKey implements PrivateKeyInterface
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
        if (Binary::safeStrlen($keyMaterial) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            $this->secretKey = $keyMaterial;
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
     * @return PublicKeyInterface
     * @throws \SodiumException
     */
    public function getPublicKey(): PublicKeyInterface
    {
        return new MontgomeryPublicKey(
            \sodium_crypto_box_publickey_from_secretkey($this->secretKey)
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