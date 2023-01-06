<?php

namespace Mrfrost\JWT\Authentication;

use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\AuthenticationException;
use CodeIgniter\Shield\Authentication\AuthenticatorInterface;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\TokenLoginModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;
use Mrfrost\JWT\Config\JWTConfig;
use Mrfrost\JWT\Encryption\JWE;
use Mrfrost\JWT\Enums\JWTType;
use Mrfrost\JWT\Exceptions\InvalidArgumentException;
use Mrfrost\JWT\JWTInterface;
use Mrfrost\JWT\Signature\JWS;

class JWTAuthenticator implements AuthenticatorInterface
{
    public JWTConfig $config;
    public JWTType $tokenType;
    public JWTInterface $JWTService;
    /**
     * The persistence engine
     */
    protected UserModel $provider;

    protected ?User $user = null;
    protected TokenLoginModel $loginModel;

    public function __construct(UserModel $provider)
    {
        helper('jwt_helper');
        /** @var JWTConfig $config */
        $config = config('JWTConfig');
        $this->config = $config;
        $this->JWTService = jwt()->getJWTService();

        $this->provider = $provider;
        $this->loginModel = model(TokenLoginModel::class);
    }

    /**
     * Attempts to authenticate a user with the given $credentials.
     * Logs the user in with a successful check.
     *
     * @throws AuthenticationException
     */
    public function attempt(array $credentials): Result
    {
        /** @var JWS $service */
        $service = $this->JWTService;
        $validator = $this->validateUser($credentials);

        // Credentials mismatch.
        if (!$validator->isOK()) {
            $this->user = null;
            unset($credentials['password']);
            return new Result([
                'success'   => false,
                'reason' => $validator->reason(),
            ]);
        }

        /** @var User $user */
        $user = $validator->extraInfo();

        $this->login($user);
        $this->user = $user;

        try {
            $token = $service
                ->create(
                    json_encode(
                        payload($user->id)
                    )
                );
        } catch (\Throwable $th) {
            return new Result([
                'success'   => false,
                'reason' => $th->getMessage(),
            ]);
        }

        return new Result([
            'success'   => true,
            'extraInfo' => $token,
        ]);
    }

    /**
     * Checks a user's $credentials to see if they match an
     * existing user.
     */
    public function check(array $credentials): Result
    {
        /** @var JWS $service */
        $service = $this->JWTService;
        /** @var IncomingRequest $request */
        $request = service('request');

        $ipAddress = $request->getIPAddress();
        $userAgent = (string) $request->getUserAgent();

        $token = $credentials['token'];
        if (strpos($credentials['token'], 'Bearer') === 0) {
            $token = trim(substr($credentials['token'], 6));
        }
        if (!$token) {
            file_put_contents(WRITEPATH . 'JWTAuth.txt', time() . " (Failed) $ipAddress $userAgent" . PHP_EOL, FILE_APPEND);
            return new Result([
                'success'   => false,
                'reason'    => "Harus menyertakan token pada Authentication Header untuk mengakses resource",
            ]);
        }

        try {
            $jwt = $service->load($token);
        } catch (\Throwable $th) {
            file_put_contents(WRITEPATH . 'JWTAuth.txt', time() . " (Failed) $ipAddress $userAgent" . PHP_EOL, FILE_APPEND);
            return new Result([
                'success'   => false,
                'reason'    => $th->getMessage(),
            ]);
        }

        $this->loginById(json_decode($jwt->getPayload())->sub);

        file_put_contents(WRITEPATH . 'JWTAuth.txt', time() . " (Success) $ipAddress $userAgent" . PHP_EOL, FILE_APPEND);
        return new Result([
            'success'   => true,
            'extraInfo' => $this->getUser(),
        ]);
    }

    /**
     * Checks if the user is currently logged in.
     */
    public function loggedIn(): bool
    {
        if (!empty($this->user)) {
            return true;
        }

        /** @var IncomingRequest $request */
        $request = service('request');

        return $this->check([
            'token' => $request->getHeaderLine(config('Auth')->authenticatorHeader['tokens']),
        ])->isOK();
    }

    /**
     * Logs the given user in.
     */
    public function login(User $user): void
    {
        $this->user = $user;
    }

    /**
     * Logs a user in based on their ID.
     * 
     * @param int|string $userId
     */
    public function loginById($userId): void
    {
        $user = $this->provider->findById($userId);

        if (empty($user)) {
            throw AuthenticationException::forInvalidUser();
        }

        $this->login($user);
    }

    /**
     * Logs the current user out.
     */
    public function logout(): void
    {
        $this->user = null;
    }

    /**
     * Returns the currently logged in user.
     */
    public function getUser(): ?User
    {
        return $this->user;
    }

    /**
     * Updates the user's last active date.
     */
    public function recordActiveDate(): void
    {
        if (!$this->user instanceof User) {
            throw new InvalidArgumentException(
                __METHOD__ . '() requires logged in user before calling.'
            );
        }

        $this->user->last_active = Time::now();

        $this->provider->updateActiveDate($this->user);
    }

    public function validateUser(array $credentials): User|Result
    {
        // Can't validate without a password.
        if (empty($credentials['password']) || count($credentials) < 2) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        // Remove the password from credentials so we can
        // check afterword.
        $givenPassword = $credentials['password'];
        unset($credentials['password']);

        // Find the existing user
        $user = $this->provider->findByCredentials($credentials);

        if ($user === null) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.badAttempt'),
            ]);
        }

        /** @var Passwords $passwords */
        $passwords = service('passwords');

        // Now, try matching the passwords.
        if (!$passwords->verify($givenPassword, $user->password_hash)) {
            return new Result([
                'success' => false,
                'reason'  => lang('Auth.invalidPassword'),
            ]);
        }

        // Check to see if the password needs to be rehashed.
        // This would be due to the hash algorithm or hash
        // cost changing since the last time that a user
        // logged in.
        if ($passwords->needsRehash($user->password_hash)) {
            $user->password_hash = $passwords->hash($givenPassword);
            $this->provider->save($user);
        }

        return new Result([
            'success'   => true,
            'extraInfo' => $user,
        ]);
    }
}