<?php

declare(strict_types=1);

namespace Mrfrost\JWT;

use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Exceptions\JWTServiceException;

class JWT
{
    protected JWTService $JWTService;

    /**
     * The JWTService type to use for this request.
     */
    protected ?JWTType $type = null;

    public function __construct(JWTService $jWTService)
    {
        $this->jWTService = $jWTService;
    }

    /**
     * Sets the JWTService type that should be used for this request.
     *
     * @return $this
     */
    public function setJWTService(?JWTType $type = null): self
    {
        if (!empty($type)) {
            $this->type = $type;
        }

        return $this;
    }

    /**
     * Returns the current authentication class.
     */
    public function getJWTService(): JWTInterface
    {
        return $this->jWTService
            ->factory($this->type);
    }

    /**
     * Returns the current jwt product, if produced.
     */
    public function product(JWTType $type = null)
    {
        $type ??= config('JWTConfig')->defaultJWTService;
        if ($this->setJWTService($type)->getJWTService()->produced()) {
            $jwt = $this->getJWTService()->getJWT();
            return $this->jWTService
                ->producer($jwt, $this->type);
        }
        return null;
    }

    /**
     * Provide magic function-access to JWTService to save use
     * from repeating code here, and to allow them have their
     * own, additional, features on top of the required ones,
     *
     * @param string[] $args
     *
     * @throws JWTServiceException
     */
    public function __call(string $method, array $args)
    {
        $JWTService = $this->JWTService->factory($this->type);

        if (method_exists($JWTService, $method)) {
            return $JWTService->{$method}(...$args);
        }
    }
}