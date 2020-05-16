<?php namespace OFFLINE\CSP\Controllers;

use Backend\Classes\Controller;
use BackendMenu;
use OFFLINE\CSP\Models\CSPLog;
use System\Classes\SettingsManager;
use Backend\Behaviors\ListController;
use Backend\Behaviors\FormController;

class CSPLogs extends Controller
{
    public $implement = [ListController::class, FormController::class];
    
    public $listConfig = 'config_list.yaml';
    public $formConfig = 'config_form.yaml';

    public $requiredPermissions = [
        'offline.csp.manage_settings' 
    ];

    public function __construct()
    {
        parent::__construct();
        BackendMenu::setContext('October.System', 'system', 'settings');
        SettingsManager::setContext('OFFLINE.CSP', 'csp_logs');
    }

    public function index_onClear()
    {
        CSPLog::truncate();

        return redirect()->refresh();
    }
}
