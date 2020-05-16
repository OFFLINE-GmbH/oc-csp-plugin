<?php

namespace OFFLINE\CSP\Classes;


class NonceInjector
{
    protected $nonce;

    public function __construct(string $nonce)
    {
        $this->nonce = $nonce;
    }

    public static function withNonce(string $nonce)
    {
        return new self($nonce);
    }

    public function inject(string $source): string
    {
        $source = preg_replace_callback('/\<script[^\>]*>/i', function ($matches) {
            return $this->addNonce($matches[0]);
        }, $source);

        $source = preg_replace_callback('/\<style[^\>]*>/i', function ($matches) {
            return $this->addNonce($matches[0]);
        }, $source);

        return $source;
    }

    /**
     * Conditionally add a nonce if none is present.
     */
    public function addNonce(string $source): string
    {
        return str_contains($source, 'nonce')
            ? $source
            : str_replace('>', sprintf(' nonce="%s">', $this->nonce), $source);

    }
}