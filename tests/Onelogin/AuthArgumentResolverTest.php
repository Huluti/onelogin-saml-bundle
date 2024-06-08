<?php
// SPDX-License-Identifier: BSD-3-Clause

declare(strict_types=1);

namespace Nbgrp\Tests\OneloginSamlBundle\Onelogin;

use Nbgrp\OneloginSamlBundle\Idp\IdpResolver;
use Nbgrp\OneloginSamlBundle\Onelogin\AuthArgumentResolver;
use Nbgrp\OneloginSamlBundle\Onelogin\AuthRegistry;
use OneLogin\Saml2\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadata;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;

/**
 * @internal
 *
 * @psalm-suppress MixedArgumentTypeCoercion
 */
#[CoversClass(AuthArgumentResolver::class)]
final class AuthArgumentResolverTest extends TestCase
{
    public function testResolve(): void
    {
        $authRegistry = new AuthRegistry();
        $idpResolver = new IdpResolver('idp');

        $defaultAuth = self::createStub(Auth::class);
        $authRegistry->addService('default', $defaultAuth);

        $additionalAuth = self::createStub(Auth::class);
        $authRegistry->addService('additional', $additionalAuth);

        $resolver = new AuthArgumentResolver($authRegistry, $idpResolver);
        $argument = new ArgumentMetadata('foo', Auth::class, false, false, null);

        $queryRequest = new Request(['idp' => 'additional']);
        $attributesRequest = new Request([], [], ['idp' => 'additional']);

        self::assertSame($additionalAuth, self::iterableValue($resolver->resolve($queryRequest, $argument)));
        self::assertSame($additionalAuth, self::iterableValue($resolver->resolve($attributesRequest, $argument)));

        self::assertSame($defaultAuth, self::iterableValue($resolver->resolve(new Request(), $argument)));
        self::assertSame($defaultAuth, self::iterableValue($resolver->resolve(new Request(['idp' => '']), $argument)));

        self::assertNull(self::iterableValue($resolver->resolve(new Request(), $argument), true));
    }

    public function testResolveWithoutIdpException(): void
    {
        $authRegistry = new AuthRegistry();
        $idpResolver = new IdpResolver('idp');
        $resolver = new AuthArgumentResolver($authRegistry, $idpResolver);
        $argument = new ArgumentMetadata('foo', Auth::class, false, false, null);

        $this->expectException(ServiceUnavailableHttpException::class);
        self::iterableValue($resolver->resolve(new Request(), $argument));
    }

    public function testResolveWithoutOneloginSettingsException(): void
    {
        $authRegistry = new AuthRegistry();
        $idpResolver = new IdpResolver('idp');
        $resolver = new AuthArgumentResolver($authRegistry, $idpResolver);
        $argument = new ArgumentMetadata('foo', Auth::class, false, false, null);

        $this->expectException(BadRequestHttpException::class);
        $this->expectExceptionMessage('There is no OneLogin PHP toolkit settings for IdP "unknown". See nbgrp_onelogin_saml config ("onelogin_settings" section).');
        self::iterableValue($resolver->resolve(new Request(['idp' => 'unknown']), $argument));
    }

    /**
     * @param iterable<Auth> $it
     */
    private static function iterableValue(iterable $it, bool $skipFirst = false): ?Auth
    {
        foreach ($it as $value) {
            if ($skipFirst) {
                $skipFirst = false;
                continue;
            }

            return $value;
        }

        return null;
    }
}
