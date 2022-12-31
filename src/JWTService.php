<?php

declare(strict_types=1);

namespace Mrfrost\JWT;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWT;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Mrfrost\JWT\Config\JWTConfig;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Exceptions\JWTServiceException;

class JWTService
{
    /**
     * Instantiated JWTService objects,
     * stored by JWT type.
     *
     * @var array<string, AuthenticatorInterface> [JWTType_value => JWTType_instance]
     */
    protected array $instances = [];

    protected array $products = [];

    public function __construct(
        protected JWTConfig $config,
        protected AlgorithmManagerFactory $algorithmManagerFactory,
        protected HeaderCheckerManagerFactory $headerCheckerManagerFactory,
        protected CompressionMethodManagerFactory $compressionMethodManagerFactory,
    ) {
    }

    /**
     * Returns an instance of the specified JWTService.
     *
     * You can pass 'default' as the JWTService and it
     * will return an instance of the first JWT specified
     * in the JWT config file.
     *
     * @param JWTType|null $type JWTService type
     *
     * @throws JWTServiceException
     */
    public function factory(?JWTType $type = null): JWTInterface
    {
        // Determine actual JWT Service type
        $type ??= $this->config->defaultJWTService;

        // Return the cached instance if we have it
        if (!empty($this->instances[$type->value])) {
            return $this->instances[$type->value];
        }


        $this->instances[$type->value] = $type->getInstance(
            $this->algorithmManagerFactory,
            $this->headerCheckerManagerFactory,
            $this->compressionMethodManagerFactory,
        );

        return $this->instances[$type->value];
    }

    public function producer(JWT $jwt, ?JWTType $type = null)
    {
        // Determine actual JWT Service type
        $type ??= $this->config->defaultJWTService;

        // Return the cached instance if we have it
        if (!empty($this->products[$type->value])) {
            return $this->products[$type->value] = $jwt;
        }


        $this->products[$type->value] = $jwt;

        return $this->products[$type->value];
    }
}