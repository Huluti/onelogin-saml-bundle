<?php declare(strict_types=1);
// SPDX-License-Identifier: BSD-3-Clause

namespace Nbgrp\OneloginSamlBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * @final
 */
class Configuration implements ConfigurationInterface
{
    /**
     * @suppress PhanPossiblyNonClassMethodCall, PhanPossiblyUndeclaredMethod, PhanUndeclaredMethod
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('nbgrp_onelogin_saml');
        $rootNode = $treeBuilder->getRootNode();

        // @formatter:off
        /** @phpstan-ignore-next-line */
        $rootNode
            ->info('nb:group OneLogin PHP Symfony Bundle configuration')
            ->children()
                ->arrayNode('onelogin_settings')
                    ->disallowNewKeysInSubsequentConfigs()
                    ->useAttributeAsKey('name')
                    ->normalizeKeys(false)
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('baseurl')
                                ->cannotBeEmpty()
                            ->end()
                            ->booleanNode('strict')->end()
                            ->booleanNode('debug')->end()
                            ->arrayNode('idp')
                                ->isRequired()
                                ->children()
                                    ->scalarNode('entityId')
                                        ->isRequired()
                                    ->end()
                                    ->arrayNode('singleSignOnService')
                                        ->isRequired()
                                        ->children()
                                            ->scalarNode('url')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('binding')
                                                ->validate()
                                                    ->ifTrue(static fn ($value): bool => !str_starts_with($value, 'urn:oasis:names:tc:SAML:2.0:bindings:'))
                                                    ->thenInvalid('invalid value.')
                                                ->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('singleLogoutService')
                                        ->children()
                                            ->scalarNode('url')->end()
                                            ->scalarNode('responseUrl')->end()
                                            ->scalarNode('binding')
                                                ->validate()
                                                    ->ifTrue(static fn ($value): bool => !str_starts_with($value, 'urn:oasis:names:tc:SAML:2.0:bindings:'))
                                                    ->thenInvalid('invalid value.')
                                                ->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->scalarNode('x509cert')->end()
                                    ->scalarNode('certFingerprint')->end()
                                    ->enumNode('certFingerprintAlgorithm')
                                        ->values(['sha1', 'sha256', 'sha384', 'sha512'])
                                    ->end()
                                    ->arrayNode('x509certMulti')
                                        ->children()
                                            ->arrayNode('signing')
                                                ->prototype('scalar')->end()
                                            ->end()
                                            ->arrayNode('encryption')
                                                ->prototype('scalar')->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                            ->arrayNode('sp')
                                ->isRequired()
                                ->children()
                                    ->scalarNode('entityId')
                                        ->isRequired()
                                    ->end()
                                    ->arrayNode('assertionConsumerService')
                                        ->isRequired()
                                        ->children()
                                            ->scalarNode('url')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('binding')
                                                ->validate()
                                                    ->ifTrue(static fn ($value): bool => !str_starts_with($value, 'urn:oasis:names:tc:SAML:2.0:bindings:'))
                                                    ->thenInvalid('invalid value.')
                                                ->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('attributeConsumingService')
                                        ->children()
                                            ->scalarNode('serviceName')->end()
                                            ->scalarNode('serviceDescription')->end()
                                            ->arrayNode('requestedAttributes')
                                                ->prototype('array')
                                                    ->children()
                                                        ->scalarNode('name')->end()
                                                        ->booleanNode('isRequired')
                                                            ->defaultFalse()
                                                        ->end()
                                                        ->scalarNode('nameFormat')->end()
                                                        ->scalarNode('friendlyName')->end()
                                                        ->arrayNode('attributeValue')->end()
                                                    ->end()
                                                ->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('singleLogoutService')
                                        ->children()
                                            ->scalarNode('url')->end()
                                            ->scalarNode('binding')
                                                ->validate()
                                                    ->ifTrue(static fn ($value): bool => !str_starts_with($value, 'urn:oasis:names:tc:SAML:2.0:bindings:'))
                                                    ->thenInvalid('invalid value.')
                                                ->end()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->scalarNode('NameIDFormat')
                                        ->validate()
                                            ->ifTrue(static fn ($value): bool => !(str_starts_with($value, 'urn:oasis:names:tc:SAML:1.1:nameid-format:') || str_starts_with($value, 'urn:oasis:names:tc:SAML:2.0:nameid-format:')))
                                            ->thenInvalid('invalid value.')
                                        ->end()
                                    ->end()
                                    ->scalarNode('x509cert')->end()
                                    ->scalarNode('privateKey')->end()
                                    ->scalarNode('x509certNew')->end()
                                ->end()
                            ->end()
                            ->arrayNode('compress')
                                ->children()
                                    ->booleanNode('requests')->end()
                                    ->booleanNode('responses')->end()
                                ->end()
                            ->end()
                            ->arrayNode('security')
                                ->children()
                                    ->booleanNode('nameIdEncrypted')->end()
                                    ->booleanNode('authnRequestsSigned')->end()
                                    ->booleanNode('logoutRequestSigned')->end()
                                    ->booleanNode('logoutResponseSigned')->end()
                                    ->booleanNode('signMetadata')->end()
                                    ->booleanNode('wantMessagesSigned')->end()
                                    ->booleanNode('wantAssertionsEncrypted')->end()
                                    ->booleanNode('wantAssertionsSigned')->end()
                                    ->booleanNode('wantNameId')->end()
                                    ->booleanNode('wantNameIdEncrypted')->end()
                                    ->variableNode('requestedAuthnContext')
                                        ->validate()
                                            ->ifTrue(static fn ($value) => !(\is_bool($value) || \is_array($value)))
                                            ->thenInvalid('must be an array or a boolean.')
                                        ->end()
                                        ->validate()
                                            ->ifTrue(static fn ($value) => \is_array($value) && array_filter($value, static fn ($item): bool => !str_starts_with($item, 'urn:oasis:names:tc:SAML:2.0:ac:classes:')))
                                            ->thenInvalid('invalid value.')
                                        ->end()
                                    ->end()
                                    ->booleanNode('wantXMLValidation')->end()
                                    ->booleanNode('relaxDestinationValidation')->end()
                                    ->booleanNode('destinationStrictlyMatches')->end()
                                    ->booleanNode('allowRepeatAttributeName')->end()
                                    ->booleanNode('rejectUnsolicitedResponsesWithInResponseTo')->end()
                                    ->enumNode('signatureAlgorithm')
                                        ->values([
                                            'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
                                            'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
                                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
                                            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
                                        ])
                                    ->end()
                                    ->enumNode('digestAlgorithm')
                                        ->values([
                                            'http://www.w3.org/2000/09/xmldsig#sha1',
                                            'http://www.w3.org/2001/04/xmlenc#sha256',
                                            'http://www.w3.org/2001/04/xmldsig-more#sha384',
                                            'http://www.w3.org/2001/04/xmlenc#sha512',
                                        ])
                                    ->end()
                                    ->enumNode('encryption_algorithm')
                                        ->values([
                                            'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
                                            'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
                                            'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
                                            'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
                                            'http://www.w3.org/2009/xmlenc11#aes128-gcm',
                                            'http://www.w3.org/2009/xmlenc11#aes192-gcm',
                                            'http://www.w3.org/2009/xmlenc11#aes256-gcm',
                                        ])
                                    ->end()
                                    ->booleanNode('lowercaseUrlencoding')->end()
                                ->end()
                            ->end()
                            ->arrayNode('contactPerson')
                                ->children()
                                    ->arrayNode('technical')
                                        ->children()
                                            ->scalarNode('givenName')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('emailAddress')
                                                ->isRequired()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('support')
                                        ->children()
                                            ->scalarNode('givenName')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('emailAddress')
                                                ->isRequired()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('administrative')
                                        ->children()
                                            ->scalarNode('givenName')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('emailAddress')
                                                ->isRequired()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('billing')
                                        ->children()
                                            ->scalarNode('givenName')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('emailAddress')
                                                ->isRequired()
                                            ->end()
                                        ->end()
                                    ->end()
                                    ->arrayNode('other')
                                        ->children()
                                            ->scalarNode('givenName')
                                                ->isRequired()
                                            ->end()
                                            ->scalarNode('emailAddress')
                                                ->isRequired()
                                            ->end()
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                            ->arrayNode('organization')
                                ->arrayPrototype()
                                     ->children()
                                        ->scalarNode('name')
                                            ->isRequired()
                                        ->end()
                                        ->scalarNode('displayname')
                                            ->isRequired()
                                        ->end()
                                        ->scalarNode('url')
                                            ->isRequired()
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                        ->validate()
                            ->ifTrue(static fn ($value): bool => empty($value['organization']))
                            ->then(static fn ($value): array => array_diff_key($value, ['organization' => null]))
                        ->end()
                    ->end()
                ->end()
                ->booleanNode('use_proxy_vars')
                    ->defaultFalse()
                ->end()
                ->scalarNode('idp_parameter_name')
                    ->cannotBeEmpty()
                    ->defaultValue('idp')
                ->end()
                ->scalarNode('entity_manager_name')
                    ->cannotBeEmpty()
                ->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
