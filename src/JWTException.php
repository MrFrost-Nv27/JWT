<?php

declare(strict_types=1);

namespace Mrfrost\JWT;

use CodeIgniter\HTTP\Exceptions\HTTPException;
use Mrfrost\JWT\Exceptions\RuntimeException;

class JWTException extends RuntimeException
{
    protected $code = 400;

    public static function forNoJWTAvailable(): self
    {
        return new self(lang('JWT.JWTNotAvailable'));
    }

    public static function forInvalidJWT(): self
    {
        return new self(lang('Auth.JWTInvalid'));
    }

    /**
     * @param string $alias
     */
    public static function forNoToken(): self
    {
        return new self(lang('JWT.noToken'));
    }

    /**
     * When the cURL request (to Have I Been Pwned) in PwnedValidator
     * throws a HTTPException it is re-thrown as this one
     */
    public static function forHIBPCurlFail(HTTPException $e): self
    {
        return new self($e->getMessage(), $e->getCode(), $e);
    }
}