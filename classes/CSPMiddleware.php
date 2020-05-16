<?php

namespace OFFLINE\CSP\Classes;


use Closure;
use Illuminate\Http\Request;
use OFFLINE\CSP\Models\CSPSettings;

class CSPMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $record = CSPSettings::getSettingsRecord();
        if ( ! $record) {
            return $response;
        }

        $settings = $record->value;

        // Make sure the CSP does not break backend functionality.
        if (app()->runningInBackend()) {
            $settings = $this->patchPolicyForBackend($settings);
        }

        (new Policy($settings))
            ->configure()
            ->applyTo($response);

        return $response;
    }

    protected function patchPolicyForBackend(array $settings): array
    {
        $settings['style_src'] = $this->ensureUnsafeSources($settings['style_src']);
        $settings['script_src'] = $this->ensureUnsafeSources($settings['script_src']);
        $settings['image_src'] = $this->ensureImageSources($settings['image_src']);

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
        $settings[] = 'unsafe-inline unsafe-eval';

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
}