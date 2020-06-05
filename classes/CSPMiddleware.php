<?php

namespace OFFLINE\CSP\Classes;


use Cache;
use Closure;
use Illuminate\Http\Request;
use OFFLINE\CSP\Models\CSPSettings;
use OFFLINE\CSP\Plugin;

class CSPMiddleware
{
    const CACHE_KEYS = [
        'default' => 'offline.csp',
        'backend' => 'offline.csp.backend',
    ];

    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $record = CSPSettings::getSettingsRecord();
        if ( ! $record || ! optional($record->value)['enabled']) {
            return $response;
        }

        $headers = $this->buildHeaders($record->value);

        foreach ($headers as $name => $value) {
            if ( ! $response->headers->has($name)) {
                $response->headers->set($name, $this->patchNonce($value));
            }
        }

        return $response;
    }

    protected function buildHeaders(array $settings): array
    {
        $cacheKey = self::CACHE_KEYS['default'];

        if (app()->runningInBackend()) {
            // Make sure the CSP does not break backend functionality.
            $settings = $this->patchPolicyForBackend($settings);
            // Cache the backend policy separately
            $cacheKey = self::CACHE_KEYS['backend'];
        }

        return Cache::rememberForever($cacheKey, function () use ($settings) {
            $headers = [];
            $policy = (new Policy($settings))->configure();

            // Add support for Report-To directive
            $headerName = 'Report-To';
            $value = json_encode([
                'group' => Plugin::REPORT_ENDPOINT,
                'max_age' => 10886400,
                'endpoints' => [['url' => $policy->getReportToUrl()]],
            ], JSON_UNESCAPED_SLASHES);

            // Add the effective CSP header
            $headers[$headerName] = $value;
            $headerName = $policy->isReportOnly()
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';

            $headers[$headerName] = (string)$policy;

            $headers = $this->addSecurityHeaders($headers, $settings);

            return $headers;
        });
    }

    protected function addSecurityHeaders(array $headers, array $settings): array
    {
        if ((bool)array_get($settings, 'enable_xss_protection', false)) {
            $headers['X-XSS-Protection'] = '1; mode=block';
        }
        if ((bool)array_get($settings, 'enable_hsts', false)) {
            $headers['Strict-Transport-Security'] = 'max-age=31536000; preload';
        }
        if ((bool)array_get($settings, 'enable_x_frame_options', false)) {
            $headers['X-Frame-Options'] = 'SAMEORIGIN';
        }
        if ((bool)array_get($settings, 'enable_content_type_options', false)) {
            $headers['X-Content-Type-Options'] = 'nosniff';
        }
        if ($option = array_get($settings, 'referrer_policy', false)) {
            $headers['Referrer-Policy'] = $option;
        }

        return $headers;
    }

    protected function patchPolicyForBackend(array $settings): array
    {
        $settings['style_src'] = $this->ensureUnsafeSources($settings['style_src']);
        $settings['script_src'] = $this->ensureUnsafeSources($settings['script_src']);
        $settings['image_src'] = $this->ensureImageSources($settings['image_src']);
        $settings['require_trusted_types'] = [];

        return $settings;
    }

    protected function ensureUnsafeSources($settings): array
    {
        if ( ! is_array($settings)) {
            $settings = [];
        }
        // Make sure no nonce setting is present as it conflicts with unsafe-inline.
        $settings = array_filter($settings, function ($setting) {
            return $setting !== 'nonce';
        });
        $settings[] = 'self unsafe-inline unsafe-eval';

        return $settings;
    }

    protected function ensureImageSources($settings): array
    {
        if ( ! is_array($settings)) {
            $settings = [];
        }
        $settings[] = 'self data: *.gravatar.com';

        return $settings;
    }

    /**
     * Add a new nonce to cached responses.
     */
    protected function patchNonce(string $value): string
    {
        if (str_contains($value, 'nonce')) {
            $nonce = app('csp-nonce');
            $value = preg_replace('/\'nonce-[^\']+\'/i', "'nonce-$nonce'", $value);
        }

        return $value;
    }
}
