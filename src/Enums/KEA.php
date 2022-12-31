<?php

namespace Mrfrost\JWT\Enums;

use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;

/**
 * KEA
 * 
 * Key Encryption Algorithm
 * for JWE
 */
enum KEA: string
{
    /**
     * AESKW
     */
    case A128KW             = "A128KW";
    case A192KW             = "A192KW";
    case A256KW             = "A256KW";

    /**
     * AESGCMKW
     */
    case A128GCMKW          = "A128GCMKW";
    case A192GCMKW          = "A192GCMKW";
    case A256GCMKW          = "A256GCMKW";

    /**
     * Direct
     */
    case Dir                = "Dir";

    /**
     * ECDHES
     */
    case ECDHES             = "ECDH-ES";
    case ECDHESA128KW       = "ECDH-ES+A128KW";
    case ECDHESA192KW       = "ECDH-ES+A192KW";
    case ECDHESA256KW       = "ECDH-ES+A256KW";

    /**
     * PBES2
     */
    case PBES2HS256A128KW   = "PBES2-HS256+A128KW";
    case PBES2HS384A192KW   = "PBES2-HS384+A192KW";
    case PBES2HS512A256KW   = "PBES2-HS512+A256KW";

    /**
     * RSA
     */
    case RSA15              = "RSA1_5";
    case RSAOAEP            = "RSA-OAEP";
    case RSAOAEP256         = "RSA-OAEP-256";

    /**
     * @param $salt_size & $nb_count is only for PBES2 Algorithm
     */
    public function getInstance(int $salt_size = 64, int $nb_count = 4096)
    {
        return match ($this) {
            KEA::A128KW             => new A128KW(),
            KEA::A192KW             => new A192KW(),
            KEA::A256KW             => new A256KW(),
            KEA::A128GCMKW          => new A128GCMKW(),
            KEA::A192GCMKW          => new A192GCMKW(),
            KEA::A256GCMKW          => new A256GCMKW(),
            KEA::Dir                => new Dir(),
            KEA::ECDHES             => new ECDHES(),
            KEA::ECDHESA128KW       => new ECDHESA128KW(),
            KEA::ECDHESA192KW       => new ECDHESA192KW(),
            KEA::ECDHESA256KW       => new ECDHESA256KW(),
            KEA::PBES2HS256A128KW   => new PBES2HS256A128KW($salt_size, $nb_count),
            KEA::PBES2HS384A192KW   => new PBES2HS384A192KW($salt_size, $nb_count),
            KEA::PBES2HS512A256KW   => new PBES2HS512A256KW($salt_size, $nb_count),
            KEA::RSA15              => new RSA15(),
            KEA::RSAOAEP            => new RSAOAEP(),
            KEA::RSAOAEP256         => new RSAOAEP256(),
            default => new A256KW(),
        };
    }

    public function getType()
    {
        return AlgorithmType::KEA;
    }
}