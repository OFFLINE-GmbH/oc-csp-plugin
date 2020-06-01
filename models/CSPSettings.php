<?php

namespace OFFLINE\CSP\Models;

use Cache;
use Model;
use OFFLINE\CSP\Classes\CSPMiddleware;

class CSPSettings extends Model
{
    public $implement = ['System.Behaviors.SettingsModel'];

    public $settingsCode = 'offline_csp_settings';

    public $settingsFields = 'fields.yaml';

    public function initSettingsData()
    {
        $this->enabled = true;
        $this->report_only = true;
        $this->report_mode = 'internal';
        $this->default_src = ['self'];
        $this->require_trusted_types = ["'script'"];
        $this->script_src = ['nonce', 'unsafe-inline'];
        $this->style_src = ['self', 'nonce', 'unsafe-inline'];
        $this->object_src = ['none'];
        $this->base_uri = ['none'];
        $this->inject_nonce = true;
        $this->enable_xss_protection = true;
        $this->enable_hsts = false;
        $this->enable_x_frame_options = true;
        $this->enable_content_type_options = true;
        $this->referrer_policy = 'same-origin';
        $this->block_all_mixed_content = true;
    }

    public function afterSave()
    {
        foreach (CSPMiddleware::CACHE_KEYS as $key) {
            Cache::forget($key);
        }
    }
}
