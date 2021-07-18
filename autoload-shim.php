<?php

namespace {
    if (!extension_loaded('gmp')) {
        return;
    }
}

namespace Mdanter\Ecc\Curves {
    function gmp_init() {
        if (!\function_exists('\\gmp_init')) {
            throw new \Error('The GMP extension is not installed.');
        }
        $args = func_get_args();
        return \gmp_init(...$args);
    }
}
