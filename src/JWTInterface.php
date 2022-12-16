<?php

declare(strict_types=1);

namespace Mrfrost\JWT;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWT;
use Jose\Component\Encryption\JWE;
use Jose\Component\Signature\JWS;

interface JWTInterface
{
    /**
     * Get Payload By User.
     *
     * @throws JWTException
     */
    public function getPayload(): ?array;

    /**
     * Attempts to authenticate a user with the given $credentials.
     * Logs the user in with a successful check.
     *
     * @throws JWTException
     * 
     * @return JWS|JWE
     */
    public function generateToken();

    /**
     * Validate token with signatures
     */
    public function validateToken(string $newToken): bool;

    /**
     * Get the key
     */
    public function getKey(): ?JWK;

    /**
     * Set and Get user for payload
     */
    public function setUser(object $newUser): self;
    public function getUser(): ?object;

    /**
     * Set and Get jWT
     * 
     * @return JWS|JWE
     */
    public function setJwT(JWT $newJWT): self;
    public function getJwT();

    /**
     * Set and Get token
     */
    public function setToken(string $newJWT): self;
    public function getToken();
    public function serializeJWT(): self;
}