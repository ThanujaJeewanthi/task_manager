<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'type',
        'username',
        'name',
        'email',
        'password',
        'phone_number',
        'user_role_id',
        'company_id',
        'active',
        'created_by',
        'updated_by',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'active' => 'boolean',
    ];

    /**
     * Get the user role.
     */
    public function userRole(): BelongsTo
    {
        return $this->belongsTo(UserRole::class, 'user_role_id');
    }

    /**
     * Get the company.
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class, 'company_id');
    }

    /**
     * Get the role name in lowercase.
     */
    public function roleName()
    {
        return strtolower($this->userRole->name ?? '');
    }

    /**
     * Get the user role.
     */
    public function hasRole()
    {
        return $this->userRole;
    }

    /**
     * Check if user is admin.
     */
    public function isAdmin()
    {
        return $this->userRole && strtolower($this->userRole->name) === 'admin';
    }

    /**
     * Get the user who created this user.
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Get the user who last updated this user.
     */
    public function updater(): BelongsTo
    {
        return $this->belongsTo(User::class, 'updated_by');
    }

    /**
     * Get users created by this user.
     */
    public function createdUsers(): HasMany
    {
        return $this->hasMany(User::class, 'created_by');
    }

    /**
     * Get users updated by this user.
     */
    public function updatedUsers(): HasMany
    {
        return $this->hasMany(User::class, 'updated_by');
    }

    /**
     * Get assigned jobs.
     */
    public function assignedJobs(): HasMany
    {
        return $this->hasMany(Job::class, 'assigned_user_id');
    }

    /**
     * Get job assignments.
     */
    public function jobAssignments(): HasMany
    {
        return $this->hasMany(JobAssignment::class);
    }

    /**
     * Get task assignments through job_employees.
     */
    public function taskAssignments(): HasMany
    {
        return $this->hasMany(JobEmployee::class);
    }

    /**
     * Get jobs where user is assigned to tasks.
     */
    public function jobsWithTasks(): BelongsToMany
    {
        return $this->belongsToMany(Job::class, 'job_employees')
            ->withPivot('task_id', 'custom_task', 'start_date', 'end_date', 'duration_in_days', 'status', 'notes')
            ->withTimestamps();
    }

    /**
     * Get jobs assigned through job_assignments.
     */
    public function assignedJobsViaAssignments(): BelongsToMany
    {
        return $this->belongsToMany(Job::class, 'job_assignments')
                   ->withPivot([
                       'assignment_type', 'assigned_date', 'due_date',
                       'status', 'notes', 'assignment_notes', 'can_assign_tasks'
                   ])
                   ->withTimestamps()
                   ->wherePivot('active', true);
    }

    /**
     * Scope a query to only include active users.
     */
    public function scopeActive($query)
    {
        return $query->where('active', true);
    }

    /**
     * Scope a query to filter by company.
     */
    public function scopeForCompany($query, $companyId)
    {
        return $query->where('company_id', $companyId);
    }

    /**
     * Scope a query to filter by user type.
     */
    public function scopeOfType($query, $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope to filter by user role.
     */
    public function scopeWithRole($query, $roleName)
    {
        return $query->whereHas('userRole', function ($query) use ($roleName) {
            $query->where('name', $roleName);
        });
    }

    /**
     * Check if user has a specific role.
     */
    public function hasRoleName($roleName)
    {
        return $this->userRole && strtolower($this->userRole->name) === strtolower($roleName);
    }

    /**
     * Get all tasks assigned to this user.
     */
    public function getAssignedTasksForCompany($companyId)
    {
        return $this->taskAssignments()
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId)->where('active', true);
            })
            ->with(['job', 'task']);
    }

    /**
     * Check if user can be assigned to tasks (is active and in same company).
     */
    public function canBeAssignedToTasks($companyId)
    {
        return $this->active && $this->company_id === $companyId;
    }
}