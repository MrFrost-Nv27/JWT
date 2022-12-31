<?php

namespace Mrfrost\JWT\Enums;

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;

/**
 * CEA
 * 
 * Content Encryption Algorithm
 * for JWE
 */
enum CEA: string
{
    /**
     * AESGCM
     */
    case A128GCM        = "A128GCM";
    case A192GCM        = "A192GCM";
    case A256GCM        = "A256GCM";

    /**
     * AESCBC
     */
    case A128CBCHS256   = "A128CBC-HS256";
    case A192CBCHS384   = "A192CBC-HS384";
    case A256CBCHS512   = "A256CBC-HS512";

    /**
     * @param $salt_size & $nb_count is only for PBES2 Algorithm
     */
    public function getInstance(int $salt_size = 64, int $nb_count = 4096)
    {
        return match ($this) {
            CEA::A128GCM        => new A128GCM(),
            CEA::A192GCM        => new A192GCM(),
            CEA::A256GCM        => new A256GCM(),
            CEA::A128CBCHS256   => new A128CBCHS256(),
            CEA::A192CBCHS384   => new A192CBCHS384(),
            CEA::A256CBCHS512   => new A256CBCHS512(),
            default => new A256CBCHS512,
        };
    }

    public function getType()
    {
        return AlgorithmType::CEA;
    }
}