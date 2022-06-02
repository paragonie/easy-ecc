<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Tests;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\ECDSA\PublicKey;
use ParagonIE\EasyECC\Exception\NotImplementedException;
use PHPUnit\Framework\TestCase;
use SodiumException;

class EasyECCTest extends TestCase
{
    public function testDefaults()
    {
        $ecc = new EasyECC();
        $this->assertSame('sodium', $ecc->getCurveName());
    }

    private function easyEccCurves()
    {
        return [
            [new EasyECC()],
            [new EasyECC('K256')],
            [new EasyECC('P256')],
            [new EasyECC('P384')],
            [new EasyECC('P521')],
        ];
    }

    /**
     * @dataProvider easyEccCurves
     * @param EasyECC $ecc
     *
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testCongruentOps(EasyECC $ecc)
    {
        $aliceSK = $ecc->generatePrivateKey();
        /** @var PublicKey $alicePK */
        $alicePK = $aliceSK->getPublicKey();

        $goodMessage = 'This is a test message';
        $badMessage = 'This is a test message!';
        $sign = $ecc->sign($goodMessage, $aliceSK);
        $this->assertTrue($ecc->verify($goodMessage, $alicePK, $sign));
        $this->assertFalse($ecc->verify($badMessage, $alicePK, $sign));

        $bobSK = $ecc->generatePrivateKey();
        /** @var PublicKey $bobPK */
        $bobPK = $bobSK->getPublicKey();

        $this->assertNotSame(
            $alicePK->toString(),
            $bobPK->toString(),
            'Same key generated?'
        );

        // This should be equal (ECDH):
        $send = $ecc->keyExchange($aliceSK, $bobPK, true);
        $recv = $ecc->keyExchange($bobSK, $alicePK, false);
        $this->assertSame(Hex::encode($send), Hex::encode($recv), 'Key exchange');

        // This should also be equal:
        $send2 = $ecc->keyExchange($aliceSK, $bobPK, false);
        $recv2 = $ecc->keyExchange($bobSK, $alicePK, true);
        $this->assertSame(Hex::encode($send2), Hex::encode($recv2), 'Key exchange');

        // These MUST differ, since we're mixing the data in different orders:
        $this->assertNotSame(Hex::encode($send), Hex::encode($recv2), 'Key exchange');
    }
}
