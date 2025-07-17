<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // First, drop the foreign key constraint and the column
        Schema::table('job_employees', function (Blueprint $table) {
            $table->dropForeign(['employee_id']);
            $table->dropColumn('employee_id');
        });

        // Add user_id column and foreign key
        Schema::table('job_employees', function (Blueprint $table) {
            $table->foreignId('user_id')->after('job_id')->constrained('users')->cascadeOnDelete();
        });

        // Update the unique constraint
        Schema::table('job_employees', function (Blueprint $table) {
            $table->dropUnique(['job_id', 'employee_id', 'task_id']);
            $table->unique(['job_id', 'user_id', 'task_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Remove the new unique constraint
        Schema::table('job_employees', function (Blueprint $table) {
            $table->dropUnique(['job_id', 'user_id', 'task_id']);
        });

        // Drop user_id foreign key and column
        Schema::table('job_employees', function (Blueprint $table) {
            $table->dropForeign(['user_id']);
            $table->dropColumn('user_id');
        });

        // Restore employee_id column
        Schema::table('job_employees', function (Blueprint $table) {
            $table->foreignId('employee_id')->after('job_id');
        });

        // Restore the original unique constraint
        Schema::table('job_employees', function (Blueprint $table) {
            $table->unique(['job_id', 'employee_id', 'task_id']);
        });
    }
};