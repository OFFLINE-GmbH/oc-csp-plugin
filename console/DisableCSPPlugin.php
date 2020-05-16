<?php namespace OFFLINE\CSP\Console;

use Illuminate\Console\Command;
use OFFLINE\CSP\Models\CSPSettings;

class DisableCSPPlugin extends Command
{
    protected $name = 'csp:disable';
    protected $description = 'Disable the Content Security Policy Plugin';

    public function handle()
    {
        CSPSettings::set('enabled', false);
        $this->output->success('CSP Plugin disabled successfully');
    }
}
