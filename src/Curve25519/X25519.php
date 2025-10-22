<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Curve25519;

use Mdanter\Ecc\Crypto\EcDH\EcDHInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use ParagonIE\EasyECC\Exception\NotImplementedException;

/**
 * Class X25519
 * @package ParagonIE\EasyECC\Curve25519
 */
final class X25519 implements EcDHInterface
{
    /** @var MontgomerySecretKey $sk */
    protected $sk;

    /** @var MontgomeryPublicKey $pk */
    protected $pk;

    /**
     * X25519 constructor.
     * @param PrivateKeyInterface|null $sk
     * @param PublicKeyInterface|null $pk
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function __construct(?PrivateKeyInterface $sk = null, ?PublicKeyInterface $pk = null)
    {
        if ($sk) {
            $this->setSenderKey($sk);
        }
        if ($pk) {
            $this->setRecipientKey($pk);
        }
    }

    /**
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function scalarMult(): string
    {
        return \sodium_crypto_scalarmult(
            $this->sk->getAsString(),
            $this->pk->getAsString()
        );
    }

    /**
     * @param bool $isClient
     * @return string
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function keyExchange(bool $isClient): string
    {
        /** @var MontgomeryPublicKey $s_pk */
        $s_pk = $this->sk->getPublicKey();

        if ($isClient) {
            return \sodium_crypto_kx_client_session_keys(
                $this->sk->getAsString() . $s_pk->getAsString(),
                $this->pk->getAsString()
            )[0];
        }
        return \sodium_crypto_kx_server_session_keys(
            $this->sk->getAsString() . $s_pk->getAsString(),
            $this->pk->getAsString()
        )[1];
    }

    /**
     * Calculates and returns the shared key for the exchange.
     *
     * @return \GMP
     * @throws NotImplementedException
     */
    public function calculateSharedKey(): \GMP
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * @return PublicKeyInterface
     * @throws NotImplementedException
     */
    public function createMultiPartyKey(): PublicKeyInterface
    {
        throw new NotImplementedException('This is not part of the curve25519 interface');
    }

    /**
     * Sets the sender's key.
     *
     * @param PrivateKeyInterface $key
     * @return self
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function setSenderKey(PrivateKeyInterface $key): EcDHInterface
    {
        if ($key instanceof MontgomerySecretKey) {
            $this->sk = $key;
        } elseif ($key instanceof EdwardsSecretKey) {
            $this->sk = $key->getMontgomery();
        } else {
            throw new \TypeError('Only libsodium keys are allowed');
        }
        return $this;
    }

    /**
     * Sets the recipient key.
     *
     * @param  PublicKeyInterface $key
     * @return self
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function setRecipientKey(PublicKeyInterface $key): EcDHInterface
    {
        if ($key instanceof MontgomeryPublicKey) {
            $this->pk = $key;
        } elseif ($key instanceof EdwardsPublicKey) {
            $this->pk = $key->getMontgomery();
        } else {
            throw new \TypeError('Only libsodium keys are allowed');
        }
        return $this;
    }
}
