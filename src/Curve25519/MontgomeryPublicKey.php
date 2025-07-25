<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Curve25519;

use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Primitives\CurveFpInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Primitives\PointInterface;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class MontgomeryPublicKey
 * @package ParagonIE\EasyECC\Curve25519
 */
final class MontgomeryPublicKey implements PublicKeyInterface
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
     * @return CurveFpInterface
     * @throws NotImplementedException
     */
    public function getCurve(): CurveFpInterface
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
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
