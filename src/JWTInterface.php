<?php

declare(strict_types=1);

namespace Mrfrost\JWT;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWT;
use Mrfrost\JWT\Enums\AlgorithmType;
use Mrfrost\JWT\Exceptions\JWTServiceException;

interface JWTInterface
{
    /**
     * Create the token
     * Store the token and payload if success
     *
     * @throws JWTServiceException
     */
    public function create(string $payload): string;

    /**
     * Load the token
     * initiate the payload if success
     *
     * @throws JWTServiceException
     */
    public function load(string $token): JWT;

    /**
     * Checks if the JWT Service has produced the jwt.
     * JWT can be produce from creation or loader
     */
    public function produced(): bool;

    /**
     * serialize the jwt
     */
    public function serialize(?JWT $jwt): string;

    /**
     * Returns the currently jwt product.
     */
    public function getJWT();

    public function setAlgorithm(): self;
    public function getAlgorithm(): AlgorithmManager;
}