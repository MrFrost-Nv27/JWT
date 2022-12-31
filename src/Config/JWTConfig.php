<?php

namespace Mrfrost\JWT\Config;

use CodeIgniter\Config\BaseConfig;
use Mrfrost\JWT\Enums\CEA;
use Mrfrost\JWT\Enums\Compressor;
use Mrfrost\JWT\Enums\DSA;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Enums\KEA;

class JWTConfig extends BaseConfig
{
    public string $issuer = 'Shield';
    public int $tokenLifetime = YEAR;

    public JWTType $defaultJWTService = JWTType::JWS;

    public DSA $defaultDSA = DSA::HS256;
    public KEA $defaultKEA = kEA::A256KW;
    public CEA $defaultCEA = CEA::A256CBCHS512;
    public Compressor $defaultCompressor = Compressor::Deflate;

    public array $DSAKey = [
        "kty" => "oct",
        "k" => "Xa2X7vnS88xUR-xoRtvwFdMKEdaIjHW0fUjmXwAN6k9ttPw-aCdwzcWg3wga0h-9HXvz1ikpRP965b8gTIn7PVRSCtZQ3CRSrgBuJ2m9FW_3LqhWLo2Hqp-cdZ4kqfEy6A_UjijD0mzC1yA2zXkW_8J90NjPPq0jzQTPK-gndjryahkOIbQDBjuo-Z2L54UIUJKGJXLzlTnDhgoE7GNriViXbbSEQzleYj4UWUqW2NkMBlT1DFMPdPhezs8Mz0d0BAuHqvTUE6Z9hiJoBOMEFiaTs1XvPDvK9rQO1QE5TqgHv-mx4C3l0xcYJfCWxf8S3TIPg_UL8jDhlgz305mxBQ",
    ];

    public array $recipients = [
        'main' => [
            "kty" => "oct",
            "k" => "Xa2X7vnS88xUR-xoRtvwFdMKEdaIjHW0fUjmXwAN6k9ttPw-aCdwzcWg3wga0h-9HXvz1ikpRP965b8gTIn7PVRSCtZQ3CRSrgBuJ2m9FW_3LqhWLo2Hqp-cdZ4kqfEy6A_UjijD0mzC1yA2zXkW_8J90NjPPq0jzQTPK-gndjryahkOIbQDBjuo-Z2L54UIUJKGJXLzlTnDhgoE7GNriViXbbSEQzleYj4UWUqW2NkMBlT1DFMPdPhezs8Mz0d0BAuHqvTUE6Z9hiJoBOMEFiaTs1XvPDvK9rQO1QE5TqgHv-mx4C3l0xcYJfCWxf8S3TIPg_UL8jDhlgz305mxBQ",
        ]
    ];
}