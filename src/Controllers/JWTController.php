<?php

namespace Mrfrost\JWT\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\HTTP\Response;
use CodeIgniter\Shield\Authentication\Passwords;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Exceptions\ValidationException;
use Mrfrost\JWT\Authentication\JWTAuthenticator;
use Mrfrost\JWT\Filters\JWTFilter;

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

        $credentials = $this->request->getPost(setting('Auth.validFields'));
        $credentials = array_filter($credentials);
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
            'identity' => auth()->user()->username,
            'token' => $jwe,
        ]);
    }

    /**
     * Attempts to log the user in.
     */
    public function registerAction(): Response
    {
        // Validate here first, since some things,
        // like the password, can only be validated properly here.
        $users = model(setting('Auth.userProvider'));
        $rules = $this->getValidationRules();

        if (!$this->validate($rules)) {
            return $this->failValidationErrors($this->validator->getErrors());
        }

        $allowedPostFields = array_keys($rules);
        $user = new User();
        $user->fill($this->request->getPost($allowedPostFields));

        // Workaround for email only registration/login
        if ($user->username === null) {
            $user->username = null;
        }

        try {
            $users->save($user);
        } catch (ValidationException $e) {
            return $this->failValidationErrors($users->errors());
        }

        // To get the complete user object with ID, we need to get from the database
        $user = $users->findById($users->getInsertID());

        try {
            $token = jwt()->getJWTService()
                ->create(
                    json_encode(
                        payload($user)
                    )
                );
        } catch (\Throwable $th) {
            return new Result([
                'success' => false,
                'reason' => $th->getMessage(),
            ]);
        }

        return $this->respond([
            'identity' => auth()->user()->fullname,
            'token' => $token,
        ]);
    }

    public function test()
    {
        return view('Mrfrost\JWT\Views\jwt_test');
    }

    public function testAttempt()
    {
        $permission = [
            'admin.access',
        ];
        $filter = new JWTFilter();
        $this->request->setHeader(setting('Auth.authenticatorHeader')['tokens'] ?? 'Authorization', $this->request->getPost('token'));
        $testFilter = $filter->before($this->request, $permission);
        if ($testFilter) {
            return $testFilter;
        }

        // Logic test goes here
        //

        // jwt profile
        return $this->respond([
            'success' => true,
            'JWT Type' => jwt()->getJWTService()->jwtType,
            'token' => jwt()->getJWTService()->serialize(),
            'user' => auth()->getUser(),
            'group' => auth()->getUser()->getGroups(),
            'permisson' => auth()->getUser()->getPermissions(),
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
        $registrationEmailRules = array_merge(
            config('AuthSession')->emailValidationRules,
            [sprintf('is_unique[%s.secret]', $this->tables['identities'])]
        );

        return setting('Validation.registration') ?? [
            'fullname' => [
                'label' => 'Auth.username',
                'rules' => $registrationUsernameRules,
            ],
            'email' => [
                'label' => 'Auth.email',
                'rules' => $registrationEmailRules,
            ],
            'password' => [
                'label' => 'Auth.password',
                'rules' => 'required|' . Passwords::getMaxLengthRule() . '|strong_password[]',
                'errors' => [
                    'max_byte' => 'Auth.errorPasswordTooLongBytes',
                ],
            ],
        ];
    }
}
