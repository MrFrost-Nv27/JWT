<?php

namespace Mrfrost\JWT\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Mrfrost\JWT\Authentication\JWTAuthenticator;

class JWTFilter implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return mixed
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        if (!$request instanceof IncomingRequest) {
            return;
        }

        helper('setting');
        $response = \Config\Services::response();

        /** @var JWTAuthenticator $authenticator */
        $authenticator = auth('jwt')->getAuthenticator();

        $result = $authenticator->check([
            'token' => $request->getHeaderLine(setting('Auth.authenticatorHeader')['tokens'] ?? 'Authorization'),
            // 'token' => $request->getPost('token'),
        ]);

        if (!$result->isOK() || (!empty($arguments) && $result->extraInfo()->tokenCant($arguments[0]))) {
            return $response->setStatusCode(400)->setJSON([
                'message'   => $result->reason()
            ]);
        }
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return mixed
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
    }
}