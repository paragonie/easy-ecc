<?php
declare(strict_types=1);
namespace ParagonIE\EasyECC\ECDSA;

use Mdanter\Ecc\Crypto\Signature\Signature as BaseSignature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Exception\SignatureDecodeException;
use Mdanter\Ecc\Util\BinaryString;
use ParagonIE\ConstantTime\Binary;

/**
 * Class Signature
 * @package ParagonIE\EasyECC
 */
final class Signature extends BaseSignature
{
    /**
     * Returns a hexadecimal-encoded signature.
     *
     * @param int $length
     * @return string
     */
    public function toString(int $length = 0): string
    {
        $r = gmp_strval($this->getR(), 16);
        $s = gmp_strval($this->getS(), 16);
        $len = max(Binary::safeStrlen($r), Binary::safeStrlen($s), $length);
        return str_pad($r, $len, '0', STR_PAD_LEFT) .
            str_pad($s, $len, '0', STR_PAD_LEFT);
    }

    /**
     * Returns a hexadecimal-encoded signature.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * Promote an instance of the base signature type to this type.
     *
     * @param SignatureInterface $sig
     * @return self
     */
    public static function promote(SignatureInterface $sig): self
    {
        return new self($sig->getR(), $sig->getS());
    }

    /**
     * Serializes a signature from a hexadecimal string.
     *
     * @param string $hexString
     * @return self
     * @throws \SodiumException
     */
    public static function fromString(string $hexString): self
    {
        $binary = sodium_hex2bin($hexString);
        $total_length = BinaryString::length($binary);
        if (($total_length & 1) !== 0) {
            throw new SignatureDecodeException('IEEE-P1363 signatures must be an even length');
        }
        $piece_len = $total_length >> 1;
        $r = bin2hex(BinaryString::substring($binary, 0, $piece_len));
        $s = bin2hex(BinaryString::substring($binary, $piece_len, $piece_len));

        return new self(gmp_init($r, 16), gmp_init($s, 16));
    }
}
