<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Job extends Model
{
    use HasFactory;

    protected $fillable = [
        'company_id',
        'job_type_id',
        'client_id',
        'equipment_id',
        'description',
        'photos',
        'references',
        'status',
        'priority',
        'start_date',
        'due_date',
        'completed_date',
        'assigned_user_id',
        'request_approval_from',
        'approval_status',
        'approved_by',
        'rejected_by',
        'approved_at',
        'rejected_at',
        'approval_notes',
        'rejection_notes',
        'tasks_added_by',
        'employees_added_by',
        'active',
        'created_by',
        'updated_by',
    ];

    protected $casts = [
        'photos' => 'array',
        'start_date' => 'date',
        'due_date' => 'date',
        'completed_date' => 'date',
        'approved_at' => 'datetime',
        'rejected_at' => 'datetime',
        'active' => 'boolean',
    ];

    /**
     * Get the company that owns the job.
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    /**
     * Get the job type for this job.
     */
    public function jobType(): BelongsTo
    {
        return $this->belongsTo(JobType::class);
    }

    /**
     * Get the client for this job.
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class);
    }

    /**
     * Get the equipment for this job.
     */
    public function equipment(): BelongsTo
    {
        return $this->belongsTo(Equipment::class);
    }

    /**
     * Get the user assigned to this job.
     */
    public function assignedUser(): BelongsTo
    {
        return $this->belongsTo(User::class, 'assigned_user_id');
    }

    /**
     * Get the user who created this job.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Get the user who last updated this job.
     */
    public function updater(): BelongsTo
    {
        return $this->belongsTo(User::class, 'updated_by');
    }

    /**
     * Get the user who added tasks to this job.
     */
    public function tasksAddedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'tasks_added_by');
    }

    /**
     * Get the tasks for this job.
     */
    public function tasks(): HasMany
    {
        return $this->hasMany(Task::class);
    }

    /**
     * Get the user who added employees to this job.
     */
    public function employeesAddedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'employees_added_by');
    }

    /**
     * Get the users assigned to this job through job_employees table.
     */
    public function assignedUsersToTasks(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'job_employees')
            ->withPivot('task_id', 'custom_task', 'start_date', 'end_date', 'duration_in_days', 'status', 'notes')
            ->withTimestamps();
    }

    /**
     * Get the job employee assignments.
     */
    public function jobEmployees(): HasMany
    {
        return $this->hasMany(JobEmployee::class);
    }

    /**
     * Get the job assignments.
     */
    public function assignments(): HasMany
    {
        return $this->hasMany(JobAssignment::class);
    }

    /**
     * Get the job option values.
     */
    public function optionValues(): HasMany
    {
        return $this->hasMany(JobOptionValue::class);
    }

    /**
     * Get active assignments.
     */
    public function activeAssignments(): HasMany
    {
        return $this->hasMany(JobAssignment::class)->where('active', true);
    }

    /**
     * Get primary assignment.
     */
    public function primaryAssignment(): HasOne
    {
        return $this->hasOne(JobAssignment::class)
                   ->where('assignment_type', 'primary')
                   ->where('active', true);
    }

    /**
     * Get secondary assignments.
     */
    public function secondaryAssignments(): HasMany
    {
        return $this->hasMany(JobAssignment::class)
                   ->where('assignment_type', 'secondary')
                   ->where('active', true);
    }

    /**
     * Get supervisor assignments.
     */
    public function supervisorAssignments(): HasMany
    {
        return $this->hasMany(JobAssignment::class)
                   ->where('assignment_type', 'supervisor')
                   ->where('active', true);
    }

    /**
     * Get assigned users through job assignments.
     */
    public function assignedUsers(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'job_assignments')
                   ->withPivot([
                       'assignment_type', 'assigned_date', 'due_date',
                       'status', 'notes', 'assignment_notes', 'can_assign_tasks'
                   ])
                   ->withTimestamps()
                   ->wherePivot('active', true);
    }

    /**
     * Assign job to a user.
     */
    public function assignToUser($userId, $assignmentType = 'primary', $options = [])
    {
        return JobAssignment::create([
            'job_id' => $this->id,
            'user_id' => $userId,
            'assigned_by' => auth()->id(),
            'assignment_type' => $assignmentType,
            'assigned_date' => $options['assigned_date'] ?? now(),
            'due_date' => $options['due_date'] ?? $this->due_date,
            'status' => 'assigned',
            'assignment_notes' => $options['assignment_notes'] ?? null,
            'can_assign_tasks' => $options['can_assign_tasks'] ?? ($assignmentType === 'primary'),
            'active' => true,
            'created_by' => auth()->id(),
            'updated_by' => auth()->id(),
        ]);
    }

    /**
     * Get job items.
     */
    public function jobItems(): HasMany
    {
        return $this->hasMany(JobItems::class);
    }

    /**
     * Get job activity logs.
     */
    public function activityLogs(): HasMany
    {
        return $this->hasMany(JobActivityLog::class);
    }

    /**
     * Scope to filter by company.
     */
    public function scopeForCompany($query, $companyId)
    {
        return $query->where('company_id', $companyId);
    }

    /**
     * Scope to filter active jobs.
     */
    public function scopeActive($query)
    {
        return $query->where('active', true);
    }

    /**
     * Scope to filter by status.
     */
    public function scopeByStatus($query, $status)
    {
        return $query->where('status', $status);
    }

    /**
     * Scope to filter by priority.
     */
    public function scopeByPriority($query, $priority)
    {
        return $query->where('priority', $priority);
    }
}