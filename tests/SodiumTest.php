<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Tests;
use FG\ASN1\Exception\ParserException;
use ParagonIE\EasyECC\EasyECC;
use PHPUnit\Framework\TestCase;

/**
 * Class P256Test
 * @package ParagonIE\EasyECC\Tests
 */
class SodiumTest extends TestCase
{
    /** @var EasyECC */
    protected $ecc;

    /**
     * @throws \ParagonIE\EasyECC\Exception\ConfigException
     */
    public function setUp()
    {
        $this->ecc = new EasyECC('25519');
    }

    /**
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testKeyExchange()
    {
        $alice_sk = $this->ecc->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->ecc->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();
        $alice_to_bob = $this->ecc->keyExchange($alice_sk, $bob_pk, false);
        $bob_to_alice = $this->ecc->keyExchange($bob_sk, $alice_pk, true);
        $alice_to_bob2 = $this->ecc->keyExchange($alice_sk, $bob_pk, true);
        $bob_to_alice2 = $this->ecc->keyExchange($bob_sk, $alice_pk, false);
        $this->assertSame($alice_to_bob, $bob_to_alice);
        $this->assertSame($alice_to_bob2, $bob_to_alice2);
        $this->assertNotSame($alice_to_bob, $bob_to_alice2);
        $this->assertNotSame($alice_to_bob2, $bob_to_alice);
    }

    /**
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testScalarMult()
    {
        $alice_sk = $this->ecc->generatePrivateKey();
        $alice_pk = $alice_sk->getPublicKey();
        $bob_sk = $this->ecc->generatePrivateKey();
        $bob_pk = $bob_sk->getPublicKey();
        $alice_to_bob = $this->ecc->scalarmult($alice_sk, $bob_pk);
        $bob_to_alice = $this->ecc->scalarmult($bob_sk, $alice_pk);
        $this->assertSame($alice_to_bob, $bob_to_alice);
    }

    /**
     * @throws ParserException
     * @throws \SodiumException
     * @throws \TypeError
     */
    public function testSign()
    {
        $sk = $this->ecc->generatePrivateKey();
        $pk = $sk->getPublicKey();

        $message = 'sample';
        $sig = $this->ecc->sign($message, $sk);
        $this->assertTrue($this->ecc->verify($message, $pk, $sig));
        $this->assertFalse($this->ecc->verify('samplf', $pk, $sig));
    }
}
