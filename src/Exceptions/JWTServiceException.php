<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Exceptions;

use Throwable;

class JWTServiceException extends RuntimeException
{
    protected $code = 400;

    public static function forUnknownJWTService(): self
    {
        return new self("JWTService tidak tersedia");
    }

    public static function forFailedJWTCreation(string $reason): self
    {
        return new self($reason);
    }

    public static function forFailedJWTLoading(string $reason): self
    {
        return new self($reason);
    }

    public static function forFailedJWTSerialization(string $reason): self
    {
        return new self($reason);
    }
}