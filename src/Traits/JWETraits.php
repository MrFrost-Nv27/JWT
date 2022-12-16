<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Traits;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;

trait JWETraits
{
    public function getKeyEncryptionAlgorithm(): AlgorithmManager
    {
        return new AlgorithmManager([
            new A256KW(),
        ]);
    }

    public function getContentEncryptionAlgorithm(): AlgorithmManager
    {
        return new AlgorithmManager([
            new A256CBCHS512(),
        ]);
    }

    public function getCompressionMethod(): CompressionMethodManager
    {
        return new CompressionMethodManager([
            new Deflate(),
        ]);
    }

    public function getSerializer(): JWESerializer
    {
        return new CompactSerializer;
    }

    public function getSerializeManager(): JWESerializerManager
    {
        return new JWESerializerManager([
            new CompactSerializer(),
        ]);
    }

    public function getDecrypter(): JWEDecrypter
    {
        return new JWEDecrypter(
            $this->getKeyEncryptionAlgorithm(),
            $this->getContentEncryptionAlgorithm(),
            $this->getCompressionMethod()
        );
    }

    public function getHeaderChecker(): HeaderCheckerManager
    {
        return new HeaderCheckerManager(
            [
                new AlgorithmChecker([config('JWT')->JWEKeyEncryptionAlgorithm]),
            ],
            [
                new JWETokenSupport(),
            ]
        );
    }

    public function getClaimsChecker(): ClaimCheckerManager
    {
        return new ClaimCheckerManager(
            [
                new IssuerChecker([config('JWT')->issuer]),
                new IssuedAtChecker(),
                new NotBeforeChecker(),
                new ExpirationTimeChecker(),
                // new AudienceChecker('Client'),
            ]
        );
    }
}