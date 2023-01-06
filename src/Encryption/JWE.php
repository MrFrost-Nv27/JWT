<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Encryption;

use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWT;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWE as EncryptionJWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Mrfrost\JWT\Config\JWTConfig;
use Mrfrost\JWT\Enums\AlgorithmType;
use Mrfrost\JWT\Enums\CEA;
use Mrfrost\JWT\Enums\Compressor;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Enums\KEA;
use Mrfrost\JWT\Exceptions\JWTServiceException;
use Mrfrost\JWT\JWTInterface;

class JWE implements JWTInterface
{
    protected JWTConfig $config;

    protected AlgorithmManager $KEAlgorithm;
    protected AlgorithmManager $CEAlgorithm;

    protected CompressionMethodManager $compressionMethod;

    protected Compressor $compressor;
    protected KEA $KEA;
    protected CEA $CEA;
    protected JWEBuilder $builder;
    protected JWESerializerManager $serializer;
    protected JWEDecrypter $decrypter;
    protected JWELoader $loader;
    protected JWK $recipient;

    public EncryptionJWE $jwt;

    public JWTType $jwtType = JWTType::JWE;

    public function __construct(
        protected AlgorithmManagerFactory $algos,
        protected HeaderCheckerManagerFactory $headerCheckers,
        protected CompressionMethodManagerFactory $compressors,
    ) {
        /** @var JWTConfig $config */
        $config = config('JWTConfig');

        $this->config = $config;
        $this->serializer = new JWESerializerManager([new CompactSerializer()]);

        $this->builder = new JWEBuilder(
            $this->getAlgorithm(AlgorithmType::KEA),
            $this->getAlgorithm(AlgorithmType::CEA),
            $this->getCompressor()
        );

        $this->decrypter = new JWEDecrypter(
            $this->getAlgorithm(AlgorithmType::KEA),
            $this->getAlgorithm(AlgorithmType::CEA),
            $this->getCompressor()
        );

        $this->loader = new JWELoader(
            $this->serializer,
            $this->decrypter,
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
                ->withSharedProtectedHeader([
                    'alg'   => $this->KEA->value,
                    'enc'   => $this->CEA->value,
                    'zip'   => $this->compressor->value,
                ])
                ->addRecipient($this->getRecipient())
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
        $recipientIndex = 0;
        $jwe = $this->serializer->unserialize($token);
        $success = $this->decrypt($jwe);

        if (!$success) {
            throw JWTServiceException::forFailedJWTLoading('JWT Invalid');
        }

        $this->jwt = $this->loader->loadAndDecryptWithKey($token, $this->getRecipient(), $recipientIndex);

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
     * @param EncryptionJWE $jwt
     */
    public function serialize(?JWT $jwt = null): string
    {
        $recipientIndex = 0;
        $jwt ??= $this->jwt;
        if (!$jwt) {
            throw JWTServiceException::forFailedJWTSerialization('Tidak ada token yang dapat diserialisasi');
        }
        return $this->serializer->serialize($this->jwtType->getCompactType(), $jwt, $recipientIndex);
    }

    public function decrypt(JWT $jwt): bool
    {
        return $this->decrypter->decryptUsingKey($jwt, $this->getRecipient(), 0);
    }

    public function setAlgorithm(AlgorithmType $type = null, $algo = null): self
    {
        if (!empty($algo)) {
            $this->algos->add($algo->value, $algo->getInstance());
            if ($type === AlgorithmType::KEA) {
                $this->builder->getKeyEncryptionAlgorithmManager()->add($algo->getInstance());
            } else {
                $this->builder->getContentEncryptionAlgorithmManager()->add($algo->getInstance());
            }
        }

        return $this;
    }

    public function getAlgorithm(AlgorithmType $type = null): AlgorithmManager
    {
        $this->KEA ??= $this->config->defaultKEA;
        $this->CEA ??= $this->config->defaultCEA;

        $this->KEAlgorithm ??= $this->algos->create([$this->KEA->value]);
        $this->CEAlgorithm ??= $this->algos->create([$this->CEA->value]);

        return $type === AlgorithmType::KEA ? $this->KEAlgorithm : $this->CEAlgorithm;
    }

    public function setRecipient(JWK|array $recipient = null): self
    {
        if (!empty($algo)) {
            if ($recipient instanceof JWT) {
                $this->recipient = $recipient;
            } else {
                $this->recipient = new JWK($recipient);
            }
        }

        return $this;
    }

    public function getRecipient(): JWK
    {
        $this->recipient ??= new JWK($this->config->recipients['main']);

        return $this->recipient;
    }

    public function setCompressor(?Compressor $compressor = null): self
    {
        if (!empty($compressor)) {
            $this->compressor = $compressor;
            $this->compressors->add($compressor->value, $compressor->getInstance());
        }

        return $this;
    }

    public function getCompressor(): CompressionMethodManager
    {
        $this->compressor ??= $this->config->defaultCompressor;
        $this->compressionMethod ??= $this->compressors->create([$this->compressor->value]);

        return $this->compressionMethod;
    }
}