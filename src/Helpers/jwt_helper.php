<?php

declare(strict_types=1);

use Mrfrost\JWT\Algorithm\JWTAlgo;
use Mrfrost\JWT\Config\JWTConfig;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\JWT;

if (!function_exists('jwt')) {
    /**
     * Provides convenient access to the main JWT class
     * for JWT Service.
     *
     * @param JWTType|null $type JWTService type
     */
    function jwt(?JWTType $type = null): JWT
    {
        /** @var JWT $jwt */
        $jwt = service('jwt');

        return $jwt->setJWTService($type);
    }
}

if (!function_exists('payload')) {
    /**
     * Generate Payload Claims
     * for JWT Service.
     */
    function payload(int $sub = null, string $aud = null): array
    {
        /** @var JWTConfig $jwtconf */
        $jwtconf = config('JWTConfig');
        $pureClaims = [
            'iss' => $jwtconf->issuer,
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $jwtconf->tokenLifetime,
        ];

        $extClaims = null;

        $sub ? $extClaims['sub'] = $sub : $sub = null;
        $aud ? $extClaims['aud'] = $aud : $aud = null;

        if ($extClaims) {
            $pureClaims = array_merge($pureClaims, $extClaims);
        }

        return $pureClaims;
    }
}