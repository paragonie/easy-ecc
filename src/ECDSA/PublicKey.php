<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\ECDSA;

use FG\ASN1\Exception\ParserException;
use Mdanter\Ecc\Crypto\Key\PublicKey as BasePublicKey;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Serializer\Point\CompressedPointSerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\EasyECC\EasyECC;

/**
 * Class PublicKey
 * @package ParagonIE\EasyECC
 */
class PublicKey extends BasePublicKey
{
    /**
     * @return string
     */
    public function exportPem(): string
    {
        $serializer = new PemPublicKeySerializer(new DerPublicKeySerializer());
        return $serializer->serialize($this);
    }

    /**
     * @param string $encoded
     * @return self
     * @throws ParserException
     */
    public static function importPem(string $encoded): self
    {
        $adapter = new GmpMath();
        $serializer = new PublicKeyDerParser($adapter);

        $encoded = preg_replace('/-----(BEGIN|END) .+? PUBLIC KEY-----/', '', $encoded);
        $encoded = preg_replace('/[^A-Za-z0-9\+\/]/', '', $encoded);

        $data = Base64::decode($encoded);
        return self::promote($serializer->parse($data));
    }

    /**
     * Promote an instance of the base public key type to this type.
     *
     * @param PublicKeyInterface $key
     * @return self
     */
    public static function promote(PublicKeyInterface $key): self
    {
        return new self(EccFactory::getAdapter(), $key->getGenerator(), $key->getPoint());
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        $serializer = new CompressedPointSerializer($this->getGenerator()->getAdapter());
        return $serializer->serialize($this->getPoint());
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * @param string $hexString
     * @param string $curve
     * @return PublicKey
     */
    public static function fromString(
        string $hexString,
        string $curve = EasyECC::DEFAULT_ECDSA_CURVE
    ): self {
        $adapter = EccFactory::getAdapter();
        switch ($curve) {
            case 'K256':
                $generator = CurveFactory::getGeneratorByName('secp256k1');
                break;
            case 'P256':
                $generator = EccFactory::getNistCurves()->generator256();
                break;
            case 'P384':
                $generator = EccFactory::getNistCurves()->generator384();
                break;
            default:
                throw new \TypeError('This can only be used with ECDSA keys');
        }
        $serializer = new CompressedPointSerializer($adapter);
        $point = $serializer->unserialize($generator->getCurve(), $hexString);
        return new self($adapter, $generator, $point);
    }
}
