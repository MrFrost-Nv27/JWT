<?php

namespace Mrfrost\JWT\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\HTTP\Response;
use Mrfrost\JWT\Authentication\JWTAuthenticator;

class JWTController extends BaseController
{
    use ResponseTrait;

    protected $helpers = ['setting', 'jwt_helper'];

    /**
     * Attempts to log the user in.
     */
    public function loginAction(): Response
    {
        // Validate here first, since some things,
        // like the password, can only be validated properly here.
        $rules = $this->getValidationRules();

        if (!$this->validate($rules)) {
            return $this->failValidationErrors($this->validator->getErrors());
        }

        $credentials             = $this->request->getPost(setting('Auth.validFields'));
        $credentials             = array_filter($credentials);
        $credentials['password'] = $this->request->getPost('password');

        /** @var JWTAuthenticator $authenticator */
        $authenticator = auth('jwt')->getAuthenticator();

        // Attempt to login
        $result = $authenticator->attempt($credentials);
        if (!$result->isOK()) {
            return $this->failValidationErrors($result->reason());
        }
        /** @var JWS $jwe */
        $jwe = $result->extraInfo();

        return $this->respond([
            'identity'  => auth()->user()->username,
            'token'     => $jwe,
        ]);
    }

    /**
     * Returns the rules that should be used for validation.
     *
     * @return array<string, array<string, array<string>|string>>
     * @phpstan-return array<string, array<string, string|list<string>>>
     */
    protected function getValidationRules(): array
    {
        return setting('Validation.login') ?? [
            // 'username' => [
            //     'label' => 'Auth.username',
            //     'rules' => config('AuthSession')->usernameValidationRules,
            // ],
            'email' => [
                'label' => 'Auth.email',
                'rules' => config('AuthSession')->emailValidationRules,
            ],
            'password' => [
                'label' => 'Auth.password',
                'rules' => 'required',
            ],
        ];
    }
}