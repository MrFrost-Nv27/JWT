<?php

namespace Mrfrost\JWT\Enums;

use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;

/**
 * DSA
 * 
 * Digital Signature Algorithm
 * for JWS
 */
enum DSA: string
{
    /**
     * HMAC with SHA-2 Functions
     */
    case HS256 = "HS256";
    case HS384 = "HS384";
    case HS512 = "HS512";

    /**
     * Elliptic Curve Digital Signature Algorithm (ECDSA)
     */
    case ES256 = "ES256";
    case ES384 = "ES384";
    case ES512 = "ES512";

    /**
     * RSASSA-PKCS1 v1_5
     */
    case RS256 = "RS256";
    case RS384 = "RS384";
    case RS512 = "RS512";

    /**
     * RSASSA-PSS
     */
    case PS256 = "PS256";
    case PS384 = "PS384";
    case PS512 = "PS512";

    /**
     * Edwards-curve Digital Signature Algorithm (EdDSA)
     */
    case EdDSA = "EdDSA";

    /**
     * HMAC
     */
    case None = "None";

    public function getInstance()
    {
        return match ($this) {
            DSA::HS256 => new HS256(),
            DSA::HS384 => new HS384(),
            DSA::HS512 => new HS512(),
            DSA::ES256 => new ES256(),
            DSA::ES384 => new ES384(),
            DSA::ES512 => new ES512(),
            DSA::RS256 => new RS256(),
            DSA::RS384 => new RS384(),
            DSA::RS512 => new RS512(),
            DSA::PS256 => new PS256(),
            DSA::PS384 => new PS384(),
            DSA::PS512 => new PS512(),
            DSA::EdDSA => new EdDSA(),
            DSA::None  => new None(),
            default => new RS256(),
        };
    }

    public function getType()
    {
        return AlgorithmType::DSA;
    }
}