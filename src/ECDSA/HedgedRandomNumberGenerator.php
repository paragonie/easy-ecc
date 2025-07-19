<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\ECDSA;

use GMP;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;
use Mdanter\Ecc\Util\BinaryString;
use Mdanter\Ecc\Util\NumberSize;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\EasyECC\Exception\EasyEccException;
use TypeError;

/**
 * Class HedgedRandomNumberGenerator
 * @package ParagonIE\EasyECC\ECDSA
 */
final class HedgedRandomNumberGenerator implements RandomNumberGeneratorInterface
{
    /**
     * @var GmpMathInterface
     */
    private $math;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var PrivateKeyInterface
     */
    private $privateKey;

    /**
     * @var GMP
     */
    private $messageHash;

    /**
     * @var array<string, int>
     */
    private $algSize = array(
        'sha1' => 160,
        'sha224' => 224,
        'sha256' => 256,
        'sha384' => 384,
        'sha512' => 512
    );

    /**
     * Hedged constructor.
     *
     * @param GmpMathInterface $math
     * @param PrivateKeyInterface $privateKey
     * @param GMP $messageHash - decimal hash of the message (*may* be truncated)
     * @param string $algorithm - hashing algorithm
     */
    public function __construct(
        GmpMathInterface $math,
        PrivateKeyInterface $privateKey,
        GMP $messageHash,
        string $algorithm
    ) {
        if (!isset($this->algSize[$algorithm])) {
            throw new \InvalidArgumentException('Unsupported hashing algorithm');
        }

        $this->math = $math;
        $this->algorithm = $algorithm;
        $this->privateKey = $privateKey;
        $this->messageHash = $messageHash;
    }

    /**
     * @param string $bits - binary string of bits
     * @param GMP $qlen - length of q in bits
     * @return GMP
     */
    public function bits2int(string $bits, GMP $qlen): GMP
    {
        $vlen = gmp_init(BinaryString::length($bits) * 8, 10);
        $hex = bin2hex($bits);
        $v = gmp_init($hex, 16);

        if ($this->math->cmp($vlen, $qlen) > 0) {
            $v = $this->math->rightShift($v, (int) $this->math->toString($this->math->sub($vlen, $qlen)));
        }

        return $v;
    }

    /**
     * @param GMP $int
     * @param GMP $rlen - rounded octet length
     * @return string
     */
    public function int2octets(GMP $int, GMP $rlen): string
    {
        $out = pack("H*", $this->math->decHex(gmp_strval($int, 10)));
        if (!is_string($out)) {
            throw new TypeError('pack() returned false, somehow');
        }
        $length = gmp_init(BinaryString::length($out), 10);
        if ($this->math->cmp($length, $rlen) < 0) {
            return str_pad('', (int) $this->math->toString($this->math->sub($rlen, $length)), "\x00") . $out;
        }

        if ($this->math->cmp($length, $rlen) > 0) {
            return BinaryString::substring($out, 0, (int) $this->math->toString($rlen));
        }

        return $out;
    }

    /**
     * @param string $algorithm
     * @return int
     */
    private function getHashLength(string $algorithm): int
    {
        return $this->algSize[$algorithm];
    }

    /**
     * @param GMP $max
     * @return GMP
     * @throws EasyEccException
     */
    public function generate(GMP $max): GMP
    {
        $qlen = gmp_init(NumberSize::bnNumBits($this->math, $max), 10);
        $rlen = $this->math->rightShift($this->math->add($qlen, gmp_init(7, 10)), 3);
        $hlen = $this->getHashLength($this->algorithm);
        $bx = $this->int2octets($this->privateKey->getSecret(), $rlen) . $this->int2octets($this->messageHash, $rlen);
        // This is the hedged part:
        $bx .= random_bytes(32);

        $v = str_pad('', $hlen >> 3, "\x01", STR_PAD_LEFT);
        $k = str_pad('', $hlen >> 3, "\x00", STR_PAD_LEFT);

        $v = $this->hmac($v . "\x00" . $bx, $k);
        $v = $this->hmac($v, $k);

        $v = $this->hmac($v . "\x01" . $bx, $k);
        $v = $this->hmac($v, $k);

        $t = '';
        for ($tries = 0; $tries < 1024; ++$tries) {
            $toff = gmp_init(0, 10);
            while ($this->math->cmp($toff, $rlen) < 0) {
                $v = $this->hmac($v, $k);

                $cc = min(BinaryString::length($v), (int) gmp_strval(gmp_sub($rlen, $toff), 10));
                $t .= BinaryString::substring($v, 0, $cc);
                $toff = gmp_add($toff, $cc);
            }
            $k = $this->bits2int($t, $qlen);
            if ($this->math->cmp($k, gmp_init(0, 10)) > 0 && $this->math->cmp($k, $max) < 0) {
                return $k;
            }

            $k = Hex::decode(gmp_strval($k, 16));
            $v = $this->hmac($v . "\x00", $k);
            $v = $this->hmac($v, $k);
        }
        throw new EasyEccException('Infinite loop breached');
    }

    /**
     * @param string $v
     * @param string $k
     * @return string
     */
    private function hmac(string $v, string $k): string
    {
        $v = hash_hmac($this->algorithm, $v, $k, true);
        if (!is_string($v)) {
            throw new TypeError('inner hash_hmac() returned null instead of string');
        }
        return $v;
    }
}
