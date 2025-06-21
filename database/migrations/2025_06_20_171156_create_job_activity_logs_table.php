<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateJobActivityLogsTable extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('job_activity_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('job_id')->constrained('jobs')->cascadeOnDelete();

            // Activity classification
            $table->string('activity_type'); // created, updated, assigned, approved, completed, etc.
            $table->string('activity_category'); // job, task, item, approval, assignment, status_change
            $table->enum('priority_level', ['low', 'medium', 'high', 'critical'])->default('medium');
            $table->boolean('is_major_activity')->default(false); // For highlighting important activities

            // User and context information
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('user_role')->nullable(); // Store role at time of action
            $table->ipAddress('ip_address')->nullable();

            // Activity details
            $table->text('description'); // Human-readable description
            $table->json('old_values')->nullable(); // Previous state
            $table->json('new_values')->nullable(); // New state
            $table->json('metadata')->nullable(); // Additional context data

            // Related entity information
            $table->string('related_model_type')->nullable(); // Task, JobItem, JobEmployee, etc.
            $table->unsignedBigInteger('related_model_id')->nullable();
            $table->string('related_entity_name')->nullable(); // Name/title of related entity

            // Additional tracking
            $table->foreignId('affected_user_id')->nullable()->constrained('users')->nullOnDelete(); // User who was affected by action
            $table->string('browser_info')->nullable();
            $table->boolean('active')->default(true);

            $table->timestamps();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('updated_by')->nullable()->constrained('users')->nullOnDelete();

            // Indexes for performance
            $table->index(['job_id', 'created_at']);
            $table->index(['activity_type', 'activity_category']);
            $table->index(['user_id', 'created_at']);
            $table->index(['is_major_activity', 'job_id']);
            $table->index(['related_model_type', 'related_model_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('job_activity_logs');
    }
}
