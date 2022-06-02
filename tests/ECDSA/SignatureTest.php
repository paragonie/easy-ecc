<?php
declare(strict_types=1);
namespace ECDSA;

use FG\ASN1\Exception\ParserException;
use Mdanter\Ecc\Util\BinaryString;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\EasyECC\ECDSA\SecretKey;
use ParagonIE\EasyECC\Exception\ConfigException;
use ParagonIE\EasyECC\Exception\NotImplementedException;
use PHPUnit\Framework\TestCase;

/**
 * Class SignatureTest
 * @package ECDSA
 *
 * @covers \ParagonIE\EasyECC\ECDSA\SecretKey
 * @covers \ParagonIE\EasyECC\ECDSA\PublicKey
 * @covers \ParagonIE\EasyECC\ECDSA\Signature
 */
class SignatureTest extends TestCase
{
    const PUBKEY_SIZES = [
        'K256' => 33,
        'P256' => 33,
        'P384' => 49,
        'P521' => 67
    ];

    /**
     * @throws NotImplementedException
     * @throws ParserException
     * @throws ConfigException
     * @throws \SodiumException
     */
    public function testSign()
    {
        $msg = 'this is a test message';
        foreach (EasyECC::CURVES as $curve) {
            if (!array_key_exists($curve, EasyECC::SIGNATURE_SIZES)) {
                // Not an ECDSA curve
                continue;
            }
            $sk = SecretKey::generate($curve);
            /** @var PublicKey $pk */
            $pk = $sk->getPublicKey();
            $this->assertInstanceOf(PublicKey::class, $pk);
            $this->assertSame(
                self::PUBKEY_SIZES[$curve],
                BinaryString::length($pk->toString()) >> 1,
                'Compressed public keys must be the correct length'
            );

            $ecc = new EasyECC($curve);
            $signature = $ecc->sign($msg, $sk, true);
            $this->assertSame(
                EasyECC::SIGNATURE_SIZES[$curve],
                BinaryString::length($signature) >> 1,
                'IEEE-P1363 formatted signatures must be the correct length'
            );

            $this->assertTrue(
                $ecc->verify($msg, $pk, $signature, true),
                'ECDSA signature must validate'
            );

            $this->assertFalse(
                $ecc->verify($msg . ' foo', $pk, $signature, true),
                'Invalid ECDSA signature must not validate'
            );
        }
    }
}
