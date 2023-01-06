<?php

declare(strict_types=1);

namespace Mrfrost\JWT\Config;

use CodeIgniter\Config\BaseConfig;

class JWTRoutes extends BaseConfig
{
    public array $routes = [
        'jwt' => [
            [
                'post',
                'jwt/login',
                'JWTController::loginAction',
            ],
            [
                'get',
                'jwt/test',
                'JWTController::test',
            ],
            [
                'post',
                'jwt/test',
                'JWTController::testAttempt',
            ],
        ],
    ];
}