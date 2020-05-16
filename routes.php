<?php

use OFFLINE\CSP\Models\CSPLog;

\Route::post(\OFFLINE\CSP\Plugin::REPORT_URI, function () {
    $input = file_get_contents('php://input');

    $data = object_get(json_decode($input, false), 'csp-report');
    if (!$data) {
        return response('Invalid request', 500);
    }

    $log = [];
    foreach ($data as $key => $value) {
        // The database column names match the report keys,
        // but the dashes need to be replaced by underscores.
        $key = str_replace('-', '_', $key);
        $log[$key] = $value;
    }
    // The $fillable property makes sure we only ever save values that are
    // expected. This makes sure the implementation doesn't break once
    // new fields are added to the CSP violation reports in the future.
    CSPLog::create($log);

    return response('', 204); // 204 No Content
});