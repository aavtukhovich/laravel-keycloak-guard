<?php

namespace KeycloakGuard\Exceptions;

class InvalidWellKnownException extends \UnexpectedValueException
{
    public function __construct(string $message)
    {
        $this->message = "[Keycloak Guard] {$message}";
    }
}
