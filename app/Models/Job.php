<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Job extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
      'company_id',

        'job_type_id',
        'client_id',
        'equipment_id',
        'request_approval_from',
        'description',
        'photos',
        'references',
        'status',
        'priority',
        'start_date',
        'due_date',
        'completed_date',
        'assigned_user_id',
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
        'job_option_values',
        'reviewed_by',
    'reviewed_at',
    'review_notes',
    'closed_at'
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
   'photos' => 'array',
        'job_option_values' => 'array',
        'start_date' => 'date',
        'due_date' => 'date',
        'completed_date' => 'date',
        'approved_at' => 'datetime',
        'rejected_at' => 'datetime',
        'added_at' => 'datetime',
         'reviewed_at' => 'datetime',
    'closed_at' => 'datetime',
    ];

    /**
     * Get the company that owns this job.
     */
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }


    /**
     * Get the job type of this job.
     */
    public function jobType(): BelongsTo
    {
        return $this->belongsTo(JobType::class);
    }


    /**
     * Get the client associated with this job.
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class);
    }

    /**
     * Get the equipment associated with this job.
     */
    public function equipment(): BelongsTo
    {
        return $this->belongsTo(Equipment::class);
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

    public function tasks()
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
     * Get the employees assigned to this job.
     */
    public function employees(): BelongsToMany
    {
        return $this->belongsToMany(Employee::class, 'job_employees')
            ->withPivot('task_id', 'custom_task', 'start_date', 'end_date', 'duration_in_days', 'status', 'notes')
            ->withTimestamps();
    }
   public function jobEmployees()
    {
        return $this->hasMany(JobEmployee::class);
    }

    public function assignments()
    {
        return $this->hasMany(JobAssignment::class);
    }

    public function activeAssignments()
    {
        return $this->hasMany(JobAssignment::class)->where('active', true);
    }

    public function primaryAssignment()
    {
        return $this->hasOne(JobAssignment::class)
                   ->where('assignment_type', 'primary')
                   ->where('active', true);
    }

    public function secondaryAssignments()
    {
        return $this->hasMany(JobAssignment::class)
                   ->where('assignment_type', 'secondary')
                   ->where('active', true);
    }

    public function supervisorAssignments()
    {
        return $this->hasMany(JobAssignment::class)
                   ->where('assignment_type', 'supervisor')
                   ->where('active', true);
    }

    public function assignedUsers()
    {
        return $this->belongsToMany(User::class, 'job_assignments')
                   ->withPivot([
                       'assignment_type', 'assigned_date', 'due_date',
                       'status', 'notes', 'assignment_notes', 'can_assign_tasks'
                   ])
                   ->withTimestamps()
                   ->wherePivot('active', true);
    }

    // NEW: Methods for job assignment
    public function assignToUser($userId, $assignmentType = 'primary', $options = [])
    {
        $assignment = JobAssignment::create([
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
            'created_by' => auth()->id()
        ]);

        // Update job status if this is the first assignment
        if ($this->status === 'pending' && $assignmentType === 'primary') {
            $this->update([

                'updated_by' => auth()->id()
            ]);
        }

        return $assignment;
    }


    public function isAssignedToUser($userId)
    {
        return $this->activeAssignments()
                   ->where('user_id', $userId)
                   ->exists();
    }

    public function getPrimaryAssignee()
    {
        return $this->primaryAssignment?->user;
    }

    public function canUserAssignTasks($userId)
    {
        return $this->activeAssignments()
                   ->where('user_id', $userId)
                   ->where('can_assign_tasks', true)
                   ->exists();
    }

    public function getUserAssignmentType($userId)
    {
        return $this->activeAssignments()
                   ->where('user_id', $userId)
                   ->first()
                   ?->assignment_type;
    }

    public function hasAcceptedAssignments()
    {
        return $this->activeAssignments()
                   ->whereIn('status', ['accepted', 'in_progress', 'completed'])
                   ->exists();
    }

    // Existing scopes and methods remain unchanged...
    public function scopeActive($query)
    {
        return $query->where('active', true);
    }

    public function scopeForCompany($query, $companyId)
    {
        return $query->where('company_id', $companyId);
    }

    public function scopeByStatus($query, $status)
    {
        return $query->where('status', $status);
    }

    public function scopeByPriority($query, $priority)
    {
        return $query->where('priority', $priority);
    }

    public function scopeOverdue($query)
    {
        return $query->where('due_date', '<', now())
                    ->whereNotIn('status', ['completed', 'cancelled']);
    }

    public function getIsOverdueAttribute()
    {
        return $this->due_date &&
               now()->isAfter($this->due_date) &&
               !in_array($this->status, ['completed', 'cancelled']);
    }

    public function getProgressPercentageAttribute()
    {
        $totalTasks = $this->tasks()->where('active', true)->count();
        if ($totalTasks === 0) return 0;

        $completedTasks = $this->tasks()
                              ->where('active', true)
                              ->where('status', 'completed')
                              ->count();

        return round(($completedTasks / $totalTasks) * 100, 1);
    }

    public function activityLogs()
{
    return $this->hasMany(JobActivityLog::class);
}
     public function jobItems()
    {
        return $this->hasMany(JobItems::class);
    }
    public function items()
    {
        return $this->belongsToMany(JobItems::class, 'job_items')
                    ->withPivot([
                        'quantity',
                        'notes',
                        'issue_description',
                        'custom_item_description',
                        'addition_stage',
                        'added_by',
                        'added_at',
                        'active',
                        'created_by',
                        'updated_by'
                    ])
                    ->withTimestamps();
    }

    /**
     * User who approved the job
     */
    public function approvedBy()
    {
        return $this->belongsTo(User::class, 'approved_by');
    }

    /**
     * User who rejected the job
     */
    public function rejectedBy()
    {
        return $this->belongsTo(User::class, 'rejected_by');
    }

    /**
     * User assigned to the job
     */
    public function assignedUser()
    {
        return $this->belongsTo(User::class, 'assigned_user_id');
    }

    public function reviewer(): BelongsTo
{
    return $this->belongsTo(User::class, 'reviewed_by');
}

public function scopeAwaitingReview($query)
{
    return $query->where('status', 'completed')->where('active', true);
}

/**
 * Scope for closed jobs
 */
public function scopeClosed($query)
{
    return $query->where('status', 'closed');
}
// public function getStatusBadgeAttribute()
// {
//     return view('partials.status-badge', ['status' => $this->status])->render();
// }

public function getStatusColorAttribute()
{
    $statusColors = [
        'pending' => 'warning',
        'approved' => 'info',
        'in_progress' => 'primary',
        'on_hold' => 'secondary',
        'completed' => 'success',
        'closed' => 'dark',
        'cancelled' => 'danger'
    ];

    return $statusColors[$this->status] ?? 'secondary';
}

public function getStatusLabelAttribute()
{
    $statusLabels = [
        'pending' => 'Pending',
        'approved' => 'Approved',
        'in_progress' => 'In Progress',
        'on_hold' => 'On Hold',
        'completed' => 'Completed',
        'closed' => 'Closed ✓',
        'cancelled' => 'Cancelled'
    ];

    return $statusLabels[$this->status] ?? ucfirst(str_replace('_', ' ', $this->status));
}

}
