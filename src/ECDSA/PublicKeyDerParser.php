<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\ECDSA;

use Mdanter\Ecc\Crypto\Key\PublicKey;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Serializer\PublicKey\Der\Parser;

/**
 * Class DerParser
 * @package ParagonIE\EasyECC\ECDSA
 */
final class PublicKeyDerParser extends Parser
{
    /**
     * @param GeneratorPoint $generator
     * @param string $data
     * @return PublicKeyInterface
     */
    public function parseKey(GeneratorPoint $generator, string $data): PublicKeyInterface
    {
        /** @var PublicKey $pk */
        $pk = parent::parseKey($generator, $data);
        return new PublicKey(
            $generator->getAdapter(),
            $pk->getGenerator(),
            $pk->getPoint()
        );
    }
}
