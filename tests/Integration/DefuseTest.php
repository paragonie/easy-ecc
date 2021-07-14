<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Tests\Integration;

use Defuse\Crypto\Exception\BadFormatException;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use ParagonIE\EasyECC\Exception\ConfigException;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\Integration\Defuse;
use PHPUnit\Framework\TestCase;

/**
 * Class DefuseTest
 * @package ParagonIE\EasyECC\Tests\Integration
 */
class DefuseTest extends TestCase
{
    /** @var EasyECC $k256 */
    protected $k256;

    /** @var EasyECC $p256 */
    protected $p256;

    /** @var EasyECC $p384 */
    protected $p384;

    /** @var EasyECC $sodium */
    protected $sodium;

    /**
     * @throws ConfigException
     */
    public function setUp(): void
    {
        $this->k256 = new EasyECC('K256');
        $this->p256 = new EasyECC('P256');
        $this->p384 = new EasyECC('P384');
        $this->sodium = new EasyECC();
    }

    /**
     * @throws BadFormatException
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testAsymmetricEncryptK256()
    {
        $alice_sk = $this->k256->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->k256->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();

        $defuse = new Defuse($this->k256);

        $message = 'This is a test message.';
        $ciphertext = $defuse->asymmetricEncrypt($message, $alice_sk, $bob_pk);

        $this->assertSame(
            $message,
            $defuse->asymmetricDecrypt($ciphertext, $bob_sk, $alice_pk)
        );
    }

    /**
     * @throws BadFormatException
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testAsymmetricEncryptP256()
    {
        $alice_sk = $this->p256->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->p256->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();

        $defuse = new Defuse($this->p256);

        $message = 'This is a test message.';
        $ciphertext = $defuse->asymmetricEncrypt($message, $alice_sk, $bob_pk);

        $this->assertSame(
            $message,
            $defuse->asymmetricDecrypt($ciphertext, $bob_sk, $alice_pk)
        );
    }

    /**
     * @throws BadFormatException
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testAsymmetricEncryptP384()
    {
        $alice_sk = $this->p384->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->p384->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();

        $defuse = new Defuse($this->p384);

        $message = 'This is a test message.';
        $ciphertext = $defuse->asymmetricEncrypt($message, $alice_sk, $bob_pk);

        $this->assertSame(
            $message,
            $defuse->asymmetricDecrypt($ciphertext, $bob_sk, $alice_pk)
        );
    }

    /**
     * @throws BadFormatException
     * @throws EnvironmentIsBrokenException
     * @throws WrongKeyOrModifiedCiphertextException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testAsymmetricEncryptSodium()
    {
        $alice_sk = $this->sodium->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->sodium->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();

        $defuse = new Defuse($this->sodium);

        $message = 'This is a test message.';
        $ciphertext = $defuse->asymmetricEncrypt($message, $alice_sk, $bob_pk);

        $this->assertSame(
            $message,
            $defuse->asymmetricDecrypt($ciphertext, $bob_sk, $alice_pk)
        );
    }
}
