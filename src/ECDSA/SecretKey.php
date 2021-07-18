<?php
namespace ParagonIE\EasyECC\ECDSA;

use Mdanter\Ecc\Crypto\Key\PrivateKey;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class SecretKey
 * @package ParagonIE\EasyECC
 */
class SecretKey extends PrivateKey
{

    /**
     * @return string
     */
    public function exportPem(): string
    {
        $serializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer());
        return $serializer->serialize($this);
    }

    /**
     * @return PublicKeyInterface
     */
    public function getPublicKey(): PublicKeyInterface
    {
        $adapter = new GmpMath();
        $pk = parent::getPublicKey();
        return new PublicKey($adapter, $pk->getGenerator(), $pk->getPoint());
    }

    /**
     * @param string $curve
     * @return self
     * @throws NotImplementedException
     */
    public static function generate(string $curve = EasyECC::DEFAULT_ECDSA_CURVE): self
    {
        $generator = EasyECC::getGenerator($curve);
        $sk = $generator->createPrivateKey();
        $adapter = new GmpMath();
        return new self($adapter, $generator, $sk->getSecret());
    }

    /**
     * @param string $encoded
     * @return self
     */
    public static function importPem(string $encoded): self
    {
        $serializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer());
        $sk = $serializer->parse($encoded);
        if (!($sk instanceof PrivateKey)) {
            throw new \TypeError('Parsed public key MUST be an instance of the inherited class.');
        }
        return self::promote($sk);
    }

    /**
     * @param PrivateKeyInterface $key
     * @return self
     */
    public static function promote(PrivateKeyInterface $key): self
    {
        return new self(EccFactory::getAdapter(), $key->getPoint(), $key->getSecret());
    }
}
