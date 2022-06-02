<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\Tests;

use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\EasyECC\EasyECC;
use ParagonIE\EasyECC\Exception\NotImplementedException;
use PHPUnit\Framework\TestCase;
use SodiumException;

class KeyLengthTest extends TestCase
{
    public function keyProvider(): array
    {
        return [
            [88, new EasyECC('K256')],
            [91, new EasyECC('P256')],
            [120, new EasyECC('P384')],
            [158, new EasyECC('P521')]
        ];
    }

    /**
     * @dataProvider keyProvider
     *
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testKeyLength(int $expected, EasyECC $ecc): void
    {
        $sk = $ecc->generatePrivateKey();
        $pk = $sk->getPublicKey();
        $encoder = new DerPublicKeySerializer();
        $der = $encoder->serialize($pk);
        $this->assertSame($expected, Binary::safeStrlen($der), 'length mismatch');
    }
}
