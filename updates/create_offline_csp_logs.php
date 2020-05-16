<?php namespace OFFLINE\CSP\Updates;

use Schema;
use October\Rain\Database\Updates\Migration;

class CreateOfflineCspLogs extends Migration
{
    public function up()
    {
        Schema::create('offline_csp_logs', function($table)
        {
            $table->engine = 'InnoDB';
            $table->increments('id')->unsigned();
            $table->string('blocked_uri')->nullable();
            $table->string('document_uri')->nullable();
            $table->string('referrer')->nullable();
            $table->string('disposition')->nullable();
            $table->string('status_code')->nullable();
            $table->string('violated_directive')->nullable();
            $table->string('effective_directive')->nullable();
            $table->text('original_policy')->nullable();
            $table->text('script_sample')->nullable();
            $table->timestamp('created_at')->nullable();
            $table->timestamp('updated_at')->nullable();
        });
    }
    
    public function down()
    {
        Schema::dropIfExists('offline_csp_logs');
    }
}
