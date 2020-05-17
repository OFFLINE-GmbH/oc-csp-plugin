<?php namespace OFFLINE\CSP;

use Backend\Classes\FormField;
use Backend\Facades\Backend;
use Backend\FormWidgets\CodeEditor;
use Event;
use Illuminate\Contracts\Http\Kernel;
use OFFLINE\CSP\Classes\CSPMiddleware;
use OFFLINE\CSP\Classes\NonceInjector;
use OFFLINE\CSP\Classes\Policy;
use OFFLINE\CSP\Console\DisableCSPPlugin;
use OFFLINE\CSP\Models\CSPSettings;
use OFFLINE\LaravelCSP\Nonce\NonceGenerator;
use OFFLINE\LaravelCSP\Nonce\RandomString;
use System\Classes\PluginBase;
use System\Controllers\Settings;
use System\Traits\ViewMaker;

class Plugin extends PluginBase
{
    const REPORT_ENDPOINT = 'csp-endpoint';
    const REPORT_URI = '/_csp/report-uri';

    use ViewMaker;

    public function boot()
    {
        $this->app->singleton(NonceGenerator::class, RandomString::class);
        $this->app->singleton('csp-nonce', function () {
            return app(NonceGenerator::class)->generate();
        });

        // Register the CSP middleware if it is enabled.
        if ((bool)CSPSettings::get('enabled')) {
            $this->app[Kernel::class]->pushMiddleware(CSPMiddleware::class);
        }

        if (CSPSettings::get('inject_nonce')) {
            // Automatically inject the nonce attribute into each script and style tag.
            Event::listen('cms.page.postprocess', function ($controller, $url, $page, $dataHolder) {
                $dataHolder->content = NonceInjector::withNonce(app('csp-nonce'))->inject($dataHolder->content);
            });
        }

        // Register the onShowCSP handler for the backend settings page.
        \System\Controllers\Settings::extend(function ($controller) {
            $controller->addDynamicMethod('onShowCSP', function () use ($controller) {
                $csp = (string)(new Policy(post('CSPSettings', [])))->configure();

                $formWidget = $this->buildCodeEditor($controller, $csp);

                return $this->makePartial('$/offline/csp/models/cspsettings/_csp_modal.htm', [
                    'widget' => $formWidget,
                    'csp' => $csp,
                ]);
            });
        });
    }

    public function register()
    {
        $this->registerConsoleCommand('csp.disable', DisableCSPPlugin::class);
    }

    public function registerMarkupTags()
    {
        return [
            'functions' => [
                'csp_nonce' => function () {
                    return app('csp-nonce');
                },
            ],
        ];
    }

    public function registerSettings()
    {
        return [
            'csp' => [
                'label' => 'CSP',
                'description' => 'offline.csp::lang.settings.description',
                'category' => 'CSP',
                'icon' => 'icon-lock',
                'class' => CSPSettings::class,
                'order' => 600,
                'keywords' => 'csp security content policy',
                'permissions' => ['offline.csp.manage_settings'],
            ],
            'csp_logs' => [
                'label' => 'offline.csp::lang.log.label',
                'description' => 'offline.csp::lang.log.description',
                'category' => 'CSP',
                'icon' => 'icon-list',
                'url' => Backend::url('offline/csp/csplogs'),
                'order' => 601,
                'keywords' => 'csp security content policy',
                'permissions' => ['offline.csp.manage_settings'],
            ],
        ];
    }

    protected function buildCodeEditor(Settings $controller, string $csp): CodeEditor
    {
        $field = new FormField('csp', 'csp');
        $config = [
            'fontSize' => 13,
            'margin' => 15,
            'showGutter' => false,
            'displayIndentGuides' => false,
            'showPrintMargin' => false,
        ];

        // Make sure every directive starts on its own line for better visibility.
        $field->value = str_replace('; ', ";\n", $csp);

        return new CodeEditor($controller, $field, $config);
    }
}
