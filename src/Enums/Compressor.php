<?php

namespace Mrfrost\JWT\Enums;

use Jose\Component\Encryption\Compression\Deflate;

/**
 * Compressor
 * 
 * Encryption Compressor
 * for JWE
 */
enum Compressor: string
{
    case Deflate   = "DEF";

    public function getInstance()
    {
        return match ($this) {
            Compressor::Deflate => new Deflate(),
            default => new Deflate(),
        };
    }
}