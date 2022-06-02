<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Curve25519;

use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Primitives\CurveFpInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\PointInterface;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class EdwardsPublicKey
 * @package ParagonIE\EasyECC\Curve25519
 */
class EdwardsPublicKey implements PublicKeyInterface
{
    /** @var string $publicKey */
    protected $publicKey;

    /**
     * EdwardsSecretKey constructor.
     *
     * @param string $keyMaterial
     * @throws \SodiumException
     */
    public function __construct(string $keyMaterial)
    {
        if (Binary::safeStrlen($keyMaterial) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            $this->publicKey = $keyMaterial;
        } else {
            throw new \SodiumException('Invalid secret key provided');
        }
    }

    /**
     * @return string
     */
    public function getAsString(): string
    {
        return $this->publicKey;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        return Hex::encode($this->publicKey);
    }

    /**
     * @param string $str
     * @return self
     * @throws \SodiumException
     */
    public static function fromString(string $str): self
    {
        return new EdwardsPublicKey(Hex::decode($str));
    }

    /**
     * @return CurveFpInterface
     * @throws NotImplementedException
     */
    public function getCurve(): CurveFpInterface
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * @return MontgomeryPublicKey
     * @throws \SodiumException
     */
    public function getMontgomery(): MontgomeryPublicKey
    {
        return new MontgomeryPublicKey(
            \sodium_crypto_sign_ed25519_pk_to_curve25519($this->publicKey)
        );
    }

    /**
     * @return PointInterface
     * @throws NotImplementedException
     */
    public function getPoint(): PointInterface
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * @return GeneratorPoint
     * @throws NotImplementedException
     */
    public function getGenerator(): GeneratorPoint
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }
}