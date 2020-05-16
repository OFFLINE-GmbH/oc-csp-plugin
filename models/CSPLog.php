<?php namespace OFFLINE\CSP\Models;

use Model;

class CSPLog extends Model
{
    public $table = 'offline_csp_logs';
    public $fillable = [
        'blocked_uri',
        'document_uri',
        'referrer',
        'disposition',
        'status_code',
        'violated_directive',
        'effective_directive',
        'original_policy',
        'script_sample',
    ];
}
