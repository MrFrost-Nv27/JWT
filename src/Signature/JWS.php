<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Signature;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWT;
use Jose\Component\Signature\JWS as SignatureJWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Mrfrost\JWT\Config\JWTConfig;
use Mrfrost\JWT\Enums\DSA;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Exceptions\JWTServiceException;
use Mrfrost\JWT\JWTInterface;

class JWS implements JWTInterface
{
    protected JWTConfig $config;
    protected AlgorithmManager $algorithm;
    protected DSA $DSA;
    protected JWSBuilder $builder;
    protected JWSSerializerManager $serializer;
    protected JWSVerifier $verifier;
    protected JWSLoader $loader;
    protected JWK $jwk;

    protected SignatureJWS $jwt;

    public JWTType $jwtType = JWTType::JWS;

    public function __construct(
        protected AlgorithmManagerFactory $algos,
        protected HeaderCheckerManagerFactory $headerCheckers,
    ) {
        /** @var JWTConfig $config */
        $config = config('JWTConfig');

        $this->algos = $algos;
        $this->config = $config;
        $this->jwk = new JWK($config->DSAKey);
        $this->serializer = new JWSSerializerManager([
            new CompactSerializer(),
        ]);

        $this->builder = new JWSBuilder($this->getAlgorithm());
        $this->verifier = new JWSVerifier($this->getAlgorithm());
        $this->loader = new JWSLoader(
            $this->serializer,
            $this->verifier,
            $this->headerCheckers->create([$this->jwtType->value])
        );
    }

    /**
     * Create the token
     * Store the token and payload if success
     *
     * @throws JWTServiceException
     */
    public function create(string $payload): string
    {
        try {
            $jwt = $this->builder
                ->create()
                ->withPayload($payload)
                ->addSignature($this->jwk, ['alg' => $this->DSA->value])
                ->build();
        } catch (\Throwable $th) {
            throw JWTServiceException::forFailedJWTCreation($th->getMessage());
        }

        $this->jwt = $jwt;

        return $this->serialize($jwt);
    }

    /**
     * Load the token
     * initiate the payload if success
     *
     * @throws JWTServiceException
     */
    public function load(string $token): JWT
    {
        $signature = 0;
        $jws = $this->serializer->unserialize($token);
        $isVerified = $this->verify($jws);

        if (!$isVerified) {
            throw JWTServiceException::forFailedJWTLoading('JWT Invalid');
        }

        $this->jwt = $this->loader->loadAndVerifyWithKey($token, $this->jwk, $signature);

        return $this->jwt;
    }

    public function produced(): bool
    {
        $jwt = $this->jwt ?? null;
        return $jwt ? true : false;
    }

    public function getJWT()
    {
        return $this->jwt ?? null;
    }

    /**
     * serialize the jwt
     * 
     * @param SignatureJWS $jwt
     */
    public function serialize(?JWT $jwt = null): string
    {
        $jwt ??= $this->jwt;
        if (!$jwt) {
            throw JWTServiceException::forFailedJWTSerialization('Tidak ada token yang dapat diserialisasi');
        }
        return $this->serializer->serialize($this->jwtType->getCompactType(), $jwt, 0);
    }

    public function verify(JWT $jwt): bool
    {
        return $this->verifier->verifyWithKey($jwt, $this->jwk, 0);
    }

    public function setAlgorithm(?DSA $DSA = null): self
    {
        if (!empty($DSA)) {
            $this->DSA = $DSA;
            $this->algos->add($DSA->value, $DSA->getInstance());
            $this->builder->getSignatureAlgorithmManager()->add($DSA->getInstance());
        }

        return $this;
    }

    public function getAlgorithm(): AlgorithmManager
    {
        $this->DSA ??= $this->config->defaultDSA;
        $this->algorithm ??= $this->algos->create([$this->DSA->value]);

        return $this->algorithm;
    }
}