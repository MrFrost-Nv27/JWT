<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Encryption;

use Mrfrost\JWT\Exceptions\InvalidArgumentException;
use Mrfrost\JWT\Exceptions\LogicException;
use Mrfrost\JWT\Exceptions\RuntimeException;
use Mrfrost\JWT\JWTInterface;
use Mrfrost\JWT\Traits\JWETraits;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE as EncryptionJWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Mrfrost\JWT\Config\JWT as Config;
use Mrfrost\JWT\JWTException;

class JWE
{
    use JWETraits;

    protected ?array $payload;
    protected Config $config;
    protected ?JWK $encryptionKey;
    protected ?EncryptionJWE $jwt;
    protected ?string $token;
    /** @var object $user  */
    protected $user;


    public function __construct(array $options = [])
    {
        $this->config = config('JWT');
        $this->setKey($options['key'] ?? null);
        $this->setJWT($options['jwt'] ?? null);
        $this->setUser($options['user'] ?? null);
        $this->setPayload($options['payload'] ?? null);
        $this->setToken($options['token'] ?? null);
    }

    /**
     * Get Payload.
     */
    public function getPayload(): ?array
    {
        $payload = $this->payload ?? null;
        if ($payload) {
            $payload = $this->setPayloadTime($payload);
        }
        return $payload;
    }

    public function setPayload(array $payload = null): self
    {
        $input = $payload ?? $this->getPayload() ?? [];

        $payload = [
            'iss' => $this->config->issuer,
            'aud' => 'Client',
        ];

        $this->payload = $this->setPayloadTime(array_merge($payload, $input));

        return $this;
    }

    public function setPayloadTime(array $payload = null): array
    {
        return array_merge($payload, [
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $this->config->unusedTokenLifetime,
        ]);
    }

    /**
     * Generate the token
     */
    public function generateToken(): self
    {
        $payload = $this->getPayload();
        $user = $this->getUser();
        if ($payload === null) {
            throw new LogicException('Payload not found.');
        }
        if ($user === null) {
            throw new InvalidArgumentException('Payload Generator need the User Object.');
        }
        if (!$user->id) {
            throw new LogicException('id attribute is needed on user object.');
        }
        $payload = $this->payload = array_merge($payload, ['sub' => $user->id]);

        /**
         * We instantiate our JWE Builder.
         */
        $jweBuilder = new JWEBuilder(
            $this->getKeyEncryptionAlgorithm(),
            $this->getContentEncryptionAlgorithm(),
            $this->getCompressionMethod()
        );

        $jwk = $this->encryptionKey;

        $jwe = $jweBuilder
            ->create()
            ->withPayload(json_encode($payload))
            ->withSharedProtectedHeader([
                'alg' => $this->config->JWEKeyEncryptionAlgorithm,
                'enc' => $this->config->JWEContentEncryptionAlgorithm,
                'zip' => $this->config->JWECompressionMethod
            ])
            ->addRecipient($jwk->toPublic())
            ->build();

        $this->setJWT($jwe)->serializeJWT();
        return $this;
    }

    /**
     * Validate the token
     */
    public function validateToken(?string $newToken = null): bool
    {
        $token = $newToken ?? $this->getToken();
        if ($token === null) {
            throw JWTException::forNoToken();
        }
        try {
            $jwe = $this->JWEDecrypter($token, $this->getKey());
            $claimCheckerManager = $this->getClaimsChecker();

            $claims = json_decode($jwe->getPayload(), true);
            $claimCheckerManager->check($claims);
        } catch (\Throwable $th) {
            throw new RuntimeException($th->getMessage());
        }

        return true;
    }

    /**
     * Decrypt the token
     */
    public function JWEDecrypter(string $token, JWK $jwk, int $recipient = 0): EncryptionJWE
    {
        $jweLoader = new JWELoader(
            $this->getSerializeManager(),
            $this->getDecrypter(),
            $this->getHeaderChecker()
        );

        $jwe = $jweLoader->loadAndDecryptWithKey($token, $jwk, $recipient);

        return $jwe;
    }

    public static function createFromToken(string $token): self
    {
        $source = new self();
        $jwt = $source->JWEDecrypter($token, $source->getKey());
        return new self([
            'token'     => $token,
            'payload'   => json_decode($jwt->getPayload(), true),
            'jwt'       => $jwt,
        ]);
    }

    /**
     * Get and Set the key
     */
    public function getKey(): ?JWK
    {
        return $this->encryptionKey ?? null;
    }

    public function setKey(string $newKey = null): self
    {
        $key = $newKey ?? $this->config->encryptionKey ?? null;

        if ($key === null) {
            try {
                $key = file_get_contents(config("JWT")->keyFilesPath . config("JWT")->keyFilesName, true);
            } catch (\Throwable $th) {
                throw new RuntimeException("The Key doesn't exist");
            }
        }

        $this->encryptionKey = new JWK([
            "kty"   => "oct",
            "k"     => $key,
        ]);

        return $this;
    }

    /**
     * Get the User
     */
    public function getUser(): ?object
    {
        return $this->user;
    }

    /**
     * Set the User
     * 
     * @param object|null $newUser
     */
    public function setUser($newUser): self
    {
        $this->user = $newUser ?? null;
        return $this;
    }

    /**
     * Set and Get the JWT
     * 
     * @param JWE $newJWT
     */
    public function setJWT($newJWT): self
    {
        $this->jwt = $newJWT ?? null;
        return $this;
    }

    public function getJWT()
    {
        return $this->jwt ?? null;
    }

    /**
     * Set and Get the Token
     */
    public function setToken(?string $newToken): self
    {
        $this->token = $newToken ?? null;
        return $this;
    }

    public function getToken()
    {
        return $this->token ?? null;
    }

    public function serializeJWT(): self
    {
        $jwt = $this->getJWT();
        if ($jwt === null) {
            throw JWTException::forNoJWTAvailable();
        }

        if (!($jwt instanceof EncryptionJWE)) {
            throw JWTException::forInvalidJWT();
        }

        $token = null;

        try {
            $serializer = new CompactSerializer();
            $token = $serializer->serialize($jwt, 0);
            $this->setToken($token);
        } catch (\Throwable $th) {
            throw JWTException::forInvalidJWT();
        }

        return $this;
    }
}