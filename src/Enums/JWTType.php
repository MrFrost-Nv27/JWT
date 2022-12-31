<?php

namespace Mrfrost\JWT\Enums;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Mrfrost\JWT\Encryption\JWE;
use Mrfrost\JWT\Signature\JWS;

enum JWTType: string
{
    case JWS = "Signature";
    case JWE = "Encryption";

    public function getInstance(
        AlgorithmManagerFactory $algorithmManagerFactory,
        HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        CompressionMethodManagerFactory $compressionMethodManagerFactory,
    ) {
        return match ($this) {
            JWTType::JWS => new JWS(
                $algorithmManagerFactory,
                $headerCheckerManagerFactory,
            ),
            JWTType::JWE => new JWE(
                $algorithmManagerFactory,
                $headerCheckerManagerFactory,
                $compressionMethodManagerFactory
            ),
            default => new JWS(
                $algorithmManagerFactory,
                $headerCheckerManagerFactory,
            ),
        };
    }

    public function getCompactType()
    {
        return match ($this) {
            JWTType::JWS => 'jws_compact',
            JWTType::JWE => 'jwe_compact',
            default => 'jws_compact',
        };
    }
}