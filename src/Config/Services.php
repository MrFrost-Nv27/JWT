<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Config;

use Config\Services as BaseService;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Signature\JWSTokenSupport;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\JWT;
use Mrfrost\JWT\JWTService;

class Services extends BaseService
{
    public static function jwt(bool $getShared = true): JWT
    {
        if ($getShared) {
            return self::getSharedInstance('jwt');
        }

        $config = config('JWTConfig');

        $algorithmManagerFactory = new AlgorithmManagerFactory();
        $algorithmManagerFactory->add($config->defaultDSA->value, $config->defaultDSA->getInstance());
        $algorithmManagerFactory->add($config->defaultKEA->value, $config->defaultKEA->getInstance());
        $algorithmManagerFactory->add($config->defaultCEA->value, $config->defaultCEA->getInstance());

        $headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
        $headerCheckerManagerFactory->add(JWTType::JWS->value, new AlgorithmChecker([$config->defaultDSA->value]));
        $headerCheckerManagerFactory->add(JWTType::JWE->value, new AlgorithmChecker([$config->defaultKEA->value]));
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWSTokenSupport());
        $headerCheckerManagerFactory->addTokenTypeSupport(new JWETokenSupport());

        $compressionMethodManagerFactory = new CompressionMethodManagerFactory();
        $compressionMethodManagerFactory->add($config->defaultCompressor->value, $config->defaultCompressor->getInstance());

        return new JWT(new JWTService(
            $config,
            $algorithmManagerFactory,
            $headerCheckerManagerFactory,
            $compressionMethodManagerFactory,
        ));
    }
}