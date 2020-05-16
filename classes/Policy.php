<?php

namespace OFFLINE\CSP\Classes;


use OFFLINE\CSP\Plugin;
use Spatie\Csp\Directive;
use Spatie\Csp\Value;
use Symfony\Component\HttpFoundation\Response;

class Policy extends \Spatie\Csp\Policies\Policy
{
    const ENDPOINT_NAME = 'csp-endpoint';

    public $settings;

    public function __construct(array $settings)
    {
        $this->settings = (object)$settings;
    }

    /**
     * Build the CSP policy based on the configured settings.
     */
    public function configure(): parent
    {
        $this->reporting();

        $this->defaultSrc();
        $this->scriptSrc();
        $this->styleSrc();
        $this->imageSrc();
        $this->fontSrc();
        $this->connectSrc();
        $this->mediaSrc();
        $this->objectSrc();
        $this->prefetchSrc();
        $this->childSrc();
        $this->frameSrc();
        $this->workerSrc();
        $this->manifestSrc();
        $this->formAction();
        $this->baseUri();
        $this->pluginTypes();
        $this->sandbox();
        $this->flags();
        $this->requireTrustedTypes();

        $this->cleanup();

        return $this;
    }

    public function applyTo(Response $response)
    {
        $this->configure();

        // Add support for Report-To directive
        $headerName = 'Report-To';
        if ( ! $response->headers->has($headerName)) {
            $value = json_encode([
                'group' => self::ENDPOINT_NAME,
                'max_age' => 10886400,
                'endpoints' => [['url' => $this->getReportToUrl()]],
            ], JSON_UNESCAPED_SLASHES);
            $response->headers->set($headerName, $value);
        }

        $headerName = $this->reportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        if ($response->headers->has($headerName)) {
            return;
        }

        $response->headers->set($headerName, (string)$this);
    }

    protected function getReportToUrl(): string
    {
        if ($this->settings->report_mode === 'internal') {
            return Plugin::REPORT_URI;
        }

        return $this->settings->report_uri;
    }

    /**
     * Remove any invalid directives.
     */
    protected function cleanup(): void
    {
        foreach ($this->directives as $directive => $value) {
            // Any directive that contains a "none" value cannot contain any other values.
            if (is_array($value) && in_array("'none'", $value, true)) {
                $this->directives[$directive] = ["'none'"];
            }
        }
    }

    protected function reporting(): void
    {
        if ($this->settings->report_mode === 'disabled') {
            return;
        }
        if ((bool)$this->settings->report_only) {
            $this->reportOnly();
        }
        $this->reportTo($this->getReportToUrl());
    }

    public function reportTo(string $uri): parent
    {
        $this->directives['report-uri'] = [$uri];

        // $this->directives['report-to'] = [self::ENDPOINT_NAME];

        return $this;
    }

    protected function defaultSrc(): void
    {
        if ($this->settings->default_src) {
            $this->addDirective(Directive::DEFAULT, $this->join($this->settings->default_src));
        }
        if ($this->settings->default_src_hosts) {
            $this->addDirective(Directive::DEFAULT, $this->settings->default_src_hosts);
        }
    }

    protected function scriptSrc(): void
    {
        $this->addDirective(Directive::SCRIPT, 'report-sample');

        if ($this->settings->script_src) {
            $this->addDirective(Directive::SCRIPT, $this->join($this->settings->script_src));
        }
        if ($this->settings->script_src_hosts) {
            $this->addDirective(Directive::SCRIPT, $this->settings->script_src_hosts);
        }
        if ($this->checkNonce($this->settings->script_src)) {
            $this->addNonceForDirective(Directive::SCRIPT);
        }

        if ($this->settings->script_src_elem) {
            $this->addDirective(Directive::SCRIPT_ELEM, $this->join($this->settings->script_src_elem));
        }
        if ($this->settings->script_src_elem_hosts) {
            $this->addDirective(Directive::SCRIPT_ELEM, $this->settings->script_src_elem_hosts);
        }
        if ($this->checkNonce($this->settings->script_src_elem)) {
            $this->addNonceForDirective(Directive::SCRIPT_ELEM);
        }

        if ($this->settings->script_src_attr) {
            $this->addDirective(Directive::SCRIPT_ATTR, $this->join($this->settings->script_src_attr));
        }
        if ($this->settings->script_src_attr_hosts) {
            $this->addDirective(Directive::SCRIPT_ATTR, $this->settings->script_src_attr_hosts);
        }
        if ($this->checkNonce($this->settings->script_src_attr)) {
            $this->addNonceForDirective(Directive::SCRIPT_ATTR);
        }
    }

    protected function styleSrc(): void
    {
        $this->addDirective(Directive::STYLE, 'report-sample');

        if ($this->settings->style_src) {
            $this->addDirective(Directive::STYLE, $this->join($this->settings->style_src));
        }
        if ($this->settings->style_src_hosts) {
            $this->addDirective(Directive::STYLE, $this->settings->style_src_hosts);
        }
        if ($this->checkNonce($this->settings->style_src)) {
            $this->addNonceForDirective(Directive::STYLE);
        }

        if ($this->settings->style_src_elem) {
            $this->addDirective(Directive::STYLE_ELEM, $this->join($this->settings->style_src_elem));
        }
        if ($this->settings->style_src_elem_hosts) {
            $this->addDirective(Directive::STYLE_ELEM, $this->settings->style_src_elem_hosts);
        }
        if ($this->checkNonce($this->settings->style_src_elem)) {
            $this->addNonceForDirective(Directive::STYLE_ELEM);
        }

        if ($this->settings->style_src_attr) {
            $this->addDirective(Directive::STYLE_ATTR, $this->join($this->settings->style_src_attr));
        }
        if ($this->settings->style_src_attr_hosts) {
            $this->addDirective(Directive::STYLE_ATTR, $this->settings->style_src_attr_hosts);
        }
        if ($this->checkNonce($this->settings->style_src_attr)) {
            $this->addNonceForDirective(Directive::STYLE_ATTR);
        }
    }

    protected function imageSrc(): void
    {
        if ($this->settings->image_src) {
            $this->addDirective(Directive::IMG, $this->join($this->settings->image_src));
        }
        if ($this->settings->image_src_hosts) {
            $this->addDirective(Directive::IMG, $this->settings->image_src_hosts);
        }
    }

    protected function fontSrc(): void
    {
        if ($this->settings->font_src) {
            $this->addDirective(Directive::FONT, $this->join($this->settings->font_src));
        }
        if ($this->settings->font_src_hosts) {
            $this->addDirective(Directive::FONT, $this->settings->font_src_hosts);
        }
    }

    protected function connectSrc(): void
    {
        if ($this->settings->connect_src) {
            $this->addDirective(Directive::CONNECT, $this->join($this->settings->connect_src));
        }
        if ($this->settings->connect_src_hosts) {
            $this->addDirective(Directive::CONNECT, $this->settings->connect_src_hosts);
        }
    }


    protected function mediaSrc(): void
    {
        if ($this->settings->media_src) {
            $this->addDirective(Directive::MEDIA, $this->join($this->settings->media_src));
        }
        if ($this->settings->media_src_hosts) {
            $this->addDirective(Directive::MEDIA, $this->settings->media_src_hosts);
        }
    }

    protected function objectSrc(): void
    {
        if ($this->settings->object_src) {
            $this->addDirective(Directive::OBJECT, $this->join($this->settings->object_src));
        }
        if ($this->settings->object_src_hosts) {
            $this->addDirective(Directive::OBJECT, $this->settings->object_src_hosts);
        }
    }

    protected function prefetchSrc(): void
    {
        if ($this->settings->prefetch_src) {
            $this->addDirective(Directive::PREFETCH, $this->join($this->settings->prefetch_src));
        }
        if ($this->settings->prefetch_src_hosts) {
            $this->addDirective(Directive::PREFETCH, $this->settings->prefetch_src_hosts);
        }
    }


    protected function childSrc(): void
    {
        if ($this->settings->child_src) {
            $this->addDirective(Directive::CHILD, $this->join($this->settings->child_src));
        }
        if ($this->settings->child_src_hosts) {
            $this->addDirective(Directive::CHILD, $this->settings->child_src_hosts);
        }
    }

    protected function frameSrc(): void
    {
        if ($this->settings->frame_src) {
            $this->addDirective(Directive::FRAME, $this->join($this->settings->frame_src));
        }
        if ($this->settings->frame_src_hosts) {
            $this->addDirective(Directive::FRAME, $this->settings->frame_src_hosts);
        }

        if ($this->settings->frame_ancestors) {
            $this->addDirective(Directive::FRAME_ANCESTORS, $this->join($this->settings->frame_ancestors));
        }
        if ($this->settings->frame_ancestors_hosts) {
            $this->addDirective(Directive::FRAME_ANCESTORS, $this->settings->frame_ancestors_hosts);
        }
    }

    protected function workerSrc(): void
    {
        if ($this->settings->worker_src) {
            $this->addDirective(Directive::WORKER, $this->join($this->settings->worker_src));
        }
        if ($this->settings->worker_src_hosts) {
            $this->addDirective(Directive::WORKER, $this->settings->worker_src_hosts);
        }
    }

    protected function manifestSrc(): void
    {
        if ($this->settings->manifest_src) {
            $this->addDirective(Directive::MANIFEST, $this->join($this->settings->manifest_src));
        }
        if ($this->settings->manifest_src_hosts) {
            $this->addDirective(Directive::MANIFEST, $this->settings->manifest_src_hosts);
        }
    }

    protected function formAction(): void
    {
        if ($this->settings->form_action) {
            $this->addDirective(Directive::FORM_ACTION, $this->join($this->settings->form_action));
        }
        if ($this->settings->form_action_hosts) {
            $this->addDirective(Directive::FORM_ACTION, $this->settings->form_action_hosts);
        }
    }

    protected function baseUri(): void
    {
        if ($this->settings->base_uri) {
            $this->addDirective(Directive::BASE, $this->join($this->settings->base_uri));
        }
        if ($this->settings->base_uri_hosts) {
            $this->addDirective(Directive::BASE, $this->settings->base_uri_hosts);
        }
    }

    protected function pluginTypes(): void
    {
        if ($this->settings->plugin_types) {
            $this->addDirective(Directive::PLUGIN, $this->settings->plugin_types);
        }
    }

    protected function sandbox(): void
    {
        if ($this->settings->sandbox) {
            $values = array_filter($this->settings->sandbox, function ($item) {
                return $item !== 'enabled';
            });
            $this->addDirective(Directive::SANDBOX, $this->join($values));
        }
    }

    protected function flags(): void
    {
        if ((bool)$this->settings->report_only === false && (bool)$this->settings->upgrade_insecure_requests) {
            $this->addDirective(Directive::UPGRADE_INSECURE_REQUESTS, Value::NO_VALUE);
        }
        if ((bool)$this->settings->block_all_mixed_content) {
            $this->addDirective(Directive::BLOCK_ALL_MIXED_CONTENT, Value::NO_VALUE);
        }
    }

    protected function requireTrustedTypes(): void
    {
        if ($this->settings->require_trusted_types) {
            $this->addDirective(Directive::REQUIRE_TRUSTED_TYPES, $this->join($this->settings->require_trusted_types));
        }
    }

    protected function join(array $values): string
    {
        // If a directive contains the 'none' value, all other settings should be ignored.
        if (in_array('none', $values, true)) {
            return 'none';
        }

        // If a directive contains the '*' value, all other settings are unnecessary.
        if (in_array('*', $values, true)) {
            return '*';
        }

        return implode(' ', array_filter($values, function ($value) {
            return $value !== 'nonce';
        }));
    }

    protected function checkNonce($settings): bool
    {
        return is_array($settings) && in_array('nonce', $settings, true);
    }
}