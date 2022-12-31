<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Config;

use Mrfrost\JWT\Authentication\JWTAuthenticator;

class Registrar
{
    /**
     * Registers the Shield filters.
     */
    public static function Filters(): array
    {
        return [
            'aliases' => [
                'jwt'   => JWTAuthenticator::class,
            ],
        ];
    }
}