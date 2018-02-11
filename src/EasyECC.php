<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC;

use FG\ASN1\Exception\ParserException;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Util\NumberSize;
use ParagonIE\EasyECC\Curve25519\EdwardsPublicKey;
use ParagonIE\EasyECC\Curve25519\EdwardsSecretKey;
use ParagonIE\EasyECC\Curve25519\X25519;
use ParagonIE\EasyECC\Exception\ConfigException;

/**
 * Class EasyECC
 * @package ParagonIE\EasyECC
 */
class EasyECC
{
    const CURVES = ['sodium', 'P256', 'P384', 'K256'];
    const DEFAULT_CURVE = 'sodium';

    /** @var string string */
    protected $curve;

    /** @var GmpMathInterface $adapter */
    protected $adapter;

    /** @var GeneratorPoint $generator */
    protected $generator;

    /** @var string $hashAlgo */
    protected $hashAlgo;

    /** @var SignHasher $hasher */
    protected $hasher;

    /**
     * EasyECC constructor.
     * @param string $curve
     * @throws ConfigException
     */
    public function __construct(string $curve = self::DEFAULT_CURVE)
    {
        if (!\in_array($curve, self::CURVES, true)) {
            throw new ConfigException('Invalid curve choice');
        }
        $this->curve = $curve;
        switch ($curve) {
            case 'K256':
                $this->adapter = EccFactory::getAdapter();
                $this->generator = CurveFactory::getGeneratorByName('secp256k1');
                $this->hashAlgo = 'sha256';
                $this->hasher = new SignHasher($this->hashAlgo, $this->adapter);
                break;
            case 'P256':
                $this->adapter = EccFactory::getAdapter();
                $this->generator = EccFactory::getNistCurves()->generator256();
                $this->hashAlgo = 'sha256';
                $this->hasher = new SignHasher($this->hashAlgo, $this->adapter);
                break;
            case 'P384':
                $this->adapter = EccFactory::getAdapter();
                $this->generator = EccFactory::getNistCurves()->generator384();
                $this->hashAlgo = 'sha384';
                $this->hasher = new SignHasher($this->hashAlgo, $this->adapter);
                break;
            case '25519':
                break;
        }
    }

    /**
     * @return PrivateKeyInterface
     * @throws \SodiumException
     */
    public function generatePrivateKey(): PrivateKeyInterface
    {
        if ($this->curve === 'sodium') {
            return new EdwardsSecretKey(\sodium_crypto_sign_keypair());
        }
        return $this->generator->createPrivateKey();
    }

    /**
     * @param PrivateKeyInterface $private
     * @param PublicKeyInterface $public
     * @param bool $isClient
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function keyExchange(
        PrivateKeyInterface $private,
        PublicKeyInterface $public,
        bool $isClient
    ): string {
        if ($this->curve === 'sodium') {
            $ecdh = new X25519();
            $ecdh->setSenderKey($private);
            $ecdh->setRecipientKey($public);
            return $ecdh->keyExchange($isClient);
        }
        $ss = $this->scalarMult($private, $public);
        $derSer = new DerPublicKeySerializer();

        $recip_pk = $derSer->serialize($public);
        $sender_pk = $derSer->serialize($private->getPublicKey());

        if ($isClient) {
            return hash(
                $this->hashAlgo,
                $ss . $sender_pk . $recip_pk,
                true
            );
        } else {
            return hash(
                $this->hashAlgo,
                $ss . $recip_pk . $sender_pk,
                true
            );
        }
    }

    /**
     * @param PrivateKeyInterface $private
     * @param PublicKeyInterface $public
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function scalarmult(
        PrivateKeyInterface $private,
        PublicKeyInterface $public
    ): string {
        if ($this->curve === 'sodium') {
            $ecdh = new X25519();
            $ecdh->setSenderKey($private);
            $ecdh->setRecipientKey($public);
            return $ecdh->scalarMult();
        }

        $scalarmult = $private
            ->createExchange($public)
            ->calculateSharedKey();
        return $this->adapter->intToFixedSizeString(
            $scalarmult,
            NumberSize::bnNumBytes($this->adapter, $this->generator->getOrder())
        );
    }

    /**
     * @param string $message
     * @param PrivateKeyInterface $privateKey
     * @return string
     * @throws \TypeError
     */
    public function sign(
        string $message,
        PrivateKeyInterface $privateKey
    ): string {
        if ($this->curve === 'sodium') {
            if ($privateKey instanceof EdwardsSecretKey) {
                return \sodium_crypto_sign_detached(
                    $message,
                    $privateKey->getAsString()
                );
            } else {
                throw new \TypeError('Only Ed25519 secret keys can be used to sign');
            }
        }
        $hash = $this->hasher->makeHash($message, $this->generator);

        // RFC 6979
        $kGen = RandomGeneratorFactory::getHmacRandomGenerator($privateKey, $hash, $this->hashAlgo);
        $k = $kGen->generate($this->generator->getOrder());

        $signer = new Signer($this->adapter);
        $signature = $signer->sign($privateKey, $hash, $k);

        $serializer = new DerSignatureSerializer();
        return $serializer->serialize($signature);
    }

    /**
     * @param string $message
     * @param PublicKeyInterface $publicKey
     * @param string $signature
     * @return bool
     * @throws ParserException
     * @throws \TypeError
     */
    public function verify(
        string $message,
        PublicKeyInterface $publicKey,
        string $signature
    ): bool {
        if ($this->curve === 'sodium') {
            if ($publicKey instanceof EdwardsPublicKey) {
                return \sodium_crypto_sign_verify_detached(
                    $signature,
                    $message,
                    $publicKey->getAsString()
                );
            } else {
                throw new \TypeError('Only Ed25519 secret keys can be used to sign');
            }
        }

        $sigSerializer = new DerSignatureSerializer();
        $sig = $sigSerializer->parse($signature);

        $hash = $this->hasher->makeHash($message, $this->generator);
        $signer = new Signer($this->adapter);

        return $signer->verify($publicKey, $sig, $hash);
    }
}
