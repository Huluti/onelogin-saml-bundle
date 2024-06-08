<?php
// SPDX-License-Identifier: BSD-3-Clause

declare(strict_types=1);

namespace Nbgrp\Tests\OneloginSamlBundle\Security\Http\Authentication;

use Nbgrp\OneloginSamlBundle\Security\Http\Authentication\SamlAuthenticationSuccessHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * @internal
 */
#[CoversClass(SamlAuthenticationSuccessHandler::class)]
final class SamlAuthenticationSuccessHandlerTest extends TestCase
{
    public static function provideHandlerCases(): iterable
    {
        yield 'Always use default target path' => [
            'options' => [
                'always_use_default_target_path' => true,
                'default_target_path' => '/default',
            ],
            'request' => Request::create('/'),
            'expectedLocation' => 'http://localhost/default',
        ];

        yield 'Relay state from query string' => [
            'options' => [],
            'request' => Request::create('/', 'GET', [
                'RelayState' => 'http://localhost/from-query-relay-state',
            ]),
            'expectedLocation' => 'http://localhost/from-query-relay-state',
        ];

        yield 'Relay state from request' => [
            'options' => [],
            'request' => Request::create('/', 'POST', [
                'RelayState' => 'http://localhost/from-request-relay-state',
            ]),
            'expectedLocation' => 'http://localhost/from-request-relay-state',
        ];

        yield 'Relay state as login page' => [
            'options' => [
                'login_path' => '/login',
            ],
            'request' => Request::create('/', 'GET', [
                '_target_path' => '/custom',
                'RelayState' => 'http://localhost/login',
            ]),
            'expectedLocation' => 'http://localhost/custom',
        ];

        yield 'Default target path' => [
            'options' => [
                'default_target_path' => '/parent-default',
            ],
            'request' => Request::create('/'),
            'expectedLocation' => 'http://localhost/parent-default',
        ];
    }

    #[DataProvider('provideHandlerCases')]
    public function testHandler(array $options, Request $request, string $expectedLocation): void
    {
        $token = self::createStub(TokenInterface::class);
        $urlGenerator = $this->createConfiguredMock(UrlGeneratorInterface::class, [
            'generate' => 'http://localhost/login',
        ]);
        $handler = new SamlAuthenticationSuccessHandler(new HttpUtils($urlGenerator), $options);
        $response = $handler->onAuthenticationSuccess($request, $token);

        self::assertNotNull($response);
        self::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertSame($expectedLocation, $response->headers->get('Location'));
    }

    public function testEmptyRelayState(): void
    {
        $request = Request::create('/', 'GET', ['RelayState' => '']);
        $token = self::createStub(TokenInterface::class);
        $handler = new SamlAuthenticationSuccessHandler(new HttpUtils(self::createStub(UrlGeneratorInterface::class)));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot redirect to an empty URL');
        $handler->onAuthenticationSuccess($request, $token);
    }
}
