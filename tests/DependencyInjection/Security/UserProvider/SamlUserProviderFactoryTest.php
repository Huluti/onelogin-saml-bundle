<?php
// SPDX-License-Identifier: BSD-3-Clause

declare(strict_types=1);

namespace Nbgrp\Tests\OneloginSamlBundle\DependencyInjection\Security\UserProvider;

use Nbgrp\OneloginSamlBundle\DependencyInjection\Security\UserProvider\SamlUserProviderFactory;
use Nbgrp\Tests\OneloginSamlBundle\TestUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * @internal
 */
#[CoversClass(SamlUserProviderFactory::class)]
final class SamlUserProviderFactoryTest extends TestCase
{
    private SamlUserProviderFactory $factory;

    public function testDefaultConfiguration(): void
    {
        $nodeDefinition = new ArrayNodeDefinition($this->factory->getKey());
        $this->factory->addConfiguration($nodeDefinition);

        $node = $nodeDefinition->getNode();
        self::assertSame([
            'user_class' => TestUser::class,
            'default_roles' => ['ROLE_USER'],
        ], $node->finalize($node->normalize(['user_class' => TestUser::class])));
    }

    public function testNoUserClassInConfigurationException(): void
    {
        $nodeDefinition = new ArrayNodeDefinition($this->factory->getKey());
        $this->factory->addConfiguration($nodeDefinition);

        $node = $nodeDefinition->getNode();
        /** @var array $normalized */
        $normalized = $node->normalize([]);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The child config "user_class" under "saml" must be configured.');
        $node->finalize($normalized);
    }

    public function testInvalidUserClassInConfigurationException(): void
    {
        $nodeDefinition = new ArrayNodeDefinition($this->factory->getKey());
        $this->factory->addConfiguration($nodeDefinition);

        $node = $nodeDefinition->getNode();
        /** @var array $normalized */
        $normalized = $node->normalize(['user_class' => \stdClass::class]);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Invalid configuration for path "saml.user_class": You should provide user class implementing Symfony\Component\Security\Core\User\UserInterface interface.');
        $node->finalize($normalized);
    }

    public function testCreate(): void
    {
        $container = new ContainerBuilder();
        $this->factory->create($container, 'provider_id', [
            'user_class' => TestUser::class,
            'default_roles' => ['ROLE_USER'],
        ]);

        /** @var \Symfony\Component\DependencyInjection\ChildDefinition $providerDefinition */
        $providerDefinition = $container->getDefinition('provider_id');
        self::assertSame(TestUser::class, $providerDefinition->getArgument(0));
        self::assertSame(['ROLE_USER'], $providerDefinition->getArgument(1));
    }

    protected function setUp(): void
    {
        $this->factory = new SamlUserProviderFactory();
    }
}
