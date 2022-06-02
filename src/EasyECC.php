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
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Util\NumberSize;
use ParagonIE\EasyECC\Curve25519\EdwardsPublicKey;
use ParagonIE\EasyECC\Curve25519\EdwardsSecretKey;
use ParagonIE\EasyECC\Curve25519\X25519;
use ParagonIE\EasyECC\ECDSA\ConstantTimeMath;
use ParagonIE\EasyECC\ECDSA\HedgedRandomNumberGenerator;
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\EasyECC\ECDSA\Signature;
use ParagonIE\EasyECC\Exception\ConfigException;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class EasyECC
 * @package ParagonIE\EasyECC
 */
class EasyECC
{
    const CURVES = ['sodium', 'P256', 'P384', 'P521', 'K256'];
    const DEFAULT_ECDSA_CURVE = 'P256';
    const DEFAULT_CURVE = 'sodium';
    const SIGNATURE_SIZES = [
        'K256' => 64,
        'P256' => 64,
        'P384' => 96,
        'P521' => 132
    ];

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
            case 'P521':
                $this->adapter = EccFactory::getAdapter();
                $this->generator = EccFactory::getNistCurves()->generator521();
                $this->hashAlgo = 'sha512';
                $this->hasher = new SignHasher($this->hashAlgo, $this->adapter);
                break;
            case 'sodium':
                break;
        }
    }

    /**
     * @return PrivateKeyInterface
     * @throws NotImplementedException
     * @throws \SodiumException
     */
    public function generatePrivateKey(): PrivateKeyInterface
    {
        if ($this->curve === 'sodium') {
            return new EdwardsSecretKey(\sodium_crypto_sign_keypair());
        }
        return SecretKey::generate($this->curve);
    }

    /**
     * @param PrivateKeyInterface $private
     * @param PublicKeyInterface $public
     * @param bool $isClient
     * @param string $hashAlgo
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function keyExchange(
        PrivateKeyInterface $private,
        PublicKeyInterface $public,
        bool $isClient,
        string $hashAlgo = ''
    ): string {
        if ($this->curve === 'sodium') {
            $ecdh = new X25519();
            $ecdh->setSenderKey($private);
            $ecdh->setRecipientKey($public);
            return $ecdh->keyExchange($isClient);
        }
        if (empty($hashAlgo)) {
            // Use the default
            $hashAlgo = $this->hashAlgo;
        }
        $ss = $this->scalarMult($private, $public);
        $derSer = new DerPublicKeySerializer();

        $recip_pk = $derSer->serialize($public);
        $sender_pk = $derSer->serialize($private->getPublicKey());

        if ($isClient) {
            return hash(
                $hashAlgo,
                $ss . $sender_pk . $recip_pk,
                true
            );
        } else {
            return hash(
                $hashAlgo,
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
     * @param bool $ieeeFormat Set to TRUE for IEEE-P1363 formatted signatures
     * @return string
     *
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function sign(
        string $message,
        PrivateKeyInterface $privateKey,
        bool $ieeeFormat = false
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

        // RFC 6979 with additional randomness
        $kGen = new HedgedRandomNumberGenerator(
            EccFactory::getAdapter(),
            $privateKey,
            $hash,
            'sha384'
        );
        $k = $kGen->generate($this->generator->getOrder());

        // We care about leaking the one-time secret:
        $signer = new Signer(new ConstantTimeMath());
        $signature = $signer->sign($privateKey, $hash, $k);

        if ($ieeeFormat) {
            return (Signature::promote($signature))
                ->toString(self::SIGNATURE_SIZES[$this->curve]);
        }
        $serializer = new DerSignatureSerializer();
        return $serializer->serialize($signature);
    }

    /**
     * @param string $message
     * @param PublicKeyInterface $publicKey
     * @param string $signature
     * @param bool $ieeeFormat Set to TRUE for IEEE-P1363 formatted signatures
     * @return bool
     *
     * @throws ParserException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function verify(
        string $message,
        PublicKeyInterface $publicKey,
        string $signature,
        bool $ieeeFormat = false
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

        if ($ieeeFormat) {
            $sig = Signature::fromString($signature);
        } else {
            $sigSerializer = new DerSignatureSerializer();
            $sig = $sigSerializer->parse($signature);
        }

        $hash = $this->hasher->makeHash($message, $this->generator);

        // This can safely be variable-time:
        $signer = new Signer($this->adapter);

        return $signer->verify($publicKey, $sig, $hash);
    }

    /**
     * Which curve was this instantiated with?
     *
     * @return string
     */
    public function getCurveName(): string
    {
        return $this->curve;
    }

    /**
     * @param string $curve
     * @param bool $constantTime
     * @return GeneratorPoint
     * @throws NotImplementedException
     */
    public static function getGenerator(
        string $curve = self::DEFAULT_ECDSA_CURVE,
        bool $constantTime = false
    ): GeneratorPoint {
        switch ($curve) {
            case 'K256':
                return CurveFactory::getGeneratorByName('secp256k1');
            case 'P256':
                if ($constantTime) {
                    return EccFactory::getNistCurves(new ConstantTimeMath())->generator256();
                }
                return EccFactory::getNistCurves()->generator256();
            case 'P384':
                if ($constantTime) {
                    return EccFactory::getNistCurves(new ConstantTimeMath())->generator384();
                }
                return EccFactory::getNistCurves()->generator384();
            case 'P521':
                if ($constantTime) {
                    return EccFactory::getNistCurves(new ConstantTimeMath())->generator521();
                }
                return EccFactory::getNistCurves()->generator521();
            default:
                throw new NotImplementedException('This curve is not supported');
        }
    }
}
