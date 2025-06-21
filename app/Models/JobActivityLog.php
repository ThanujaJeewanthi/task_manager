<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Carbon\Carbon;

class JobActivityLog extends Model
{
    use HasFactory;

    protected $table = 'job_activity_logs';

    protected $fillable = [
        'job_id',
        'activity_type',
        'activity_category',
        'priority_level',
        'is_major_activity',
        'user_id',
        'user_role',
        'ip_address',
        'description',
        'old_values',
        'new_values',
        'metadata',
        'related_model_type',
        'related_model_id',
        'related_entity_name',
        'affected_user_id',
        'browser_info',
        'active',
        'created_by',
        'updated_by'
    ];

    protected $casts = [
        'old_values' => 'array',
        'new_values' => 'array',
        'metadata' => 'array',
        'is_major_activity' => 'boolean',
        'active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Get the job associated with this activity log.
     */
    public function job()
    {
        return $this->belongsTo(Job::class);
    }

    /**
     * Get the user who performed the activity.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the user who was affected by the activity.
     */
    public function affectedUser()
    {
        return $this->belongsTo(User::class, 'affected_user_id');
    }

    /**
     * Get the user who created this log entry.
     */
    public function createdBy()
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Get the user who last updated this log entry.
     */
    public function updatedBy()
    {
        return $this->belongsTo(User::class, 'updated_by');
    }

    /**
     * Get the related model (polymorphic relationship simulation).
     */
    public function getRelatedModelAttribute()
    {
        if (!$this->related_model_type || !$this->related_model_id) {
            return null;
        }

        $modelClass = "App\\Models\\{$this->related_model_type}";

        if (class_exists($modelClass)) {
            return $modelClass::find($this->related_model_id);
        }

        return null;
    }

    /**
     * Scope for major activities only.
     */
    public function scopeMajorActivities($query)
    {
        return $query->where('is_major_activity', true);
    }

    /**
     * Scope for specific activity category.
     */
    public function scopeByCategory($query, $category)
    {
        return $query->where('activity_category', $category);
    }

    /**
     * Scope for specific activity type.
     */
    public function scopeByType($query, $type)
    {
        return $query->where('activity_type', $type);
    }

    /**
     * Scope for specific priority level.
     */
    public function scopeByPriority($query, $priority)
    {
        return $query->where('priority_level', $priority);
    }

    /**
     * Scope for activities by specific user.
     */
    public function scopeByUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    /**
     * Scope for activities in date range.
     */
    public function scopeInDateRange($query, $startDate, $endDate)
    {
        return $query->whereBetween('created_at', [
            Carbon::parse($startDate)->startOfDay(),
            Carbon::parse($endDate)->endOfDay()
        ]);
    }

    /**
     * Get formatted activity description with context.
     */
    public function getFormattedDescriptionAttribute()
    {
        $userName = $this->user ? $this->user->name : 'System';
        $timestamp = $this->created_at->format('M d, Y H:i:s');

        return "[{$timestamp}] {$userName} ({$this->user_role}): {$this->description}";
    }

    /**
     * Get activity icon based on type and category.
     */
    public function getActivityIconAttribute()
    {
        $icons = [
            'created' => 'fas fa-plus-circle text-success',
            'updated' => 'fas fa-edit text-warning',
            'assigned' => 'fas fa-user-tag text-info',
            'approved' => 'fas fa-check-circle text-success',
            'rejected' => 'fas fa-times-circle text-danger',
            'completed' => 'fas fa-flag-checkered text-success',
            'cancelled' => 'fas fa-ban text-danger',
            'status_changed' => 'fas fa-exchange-alt text-primary',
            'item_added' => 'fas fa-plus text-info',
            'item_updated' => 'fas fa-edit text-warning',
            'task_created' => 'fas fa-tasks text-primary',
            'task_assigned' => 'fas fa-user-plus text-info',
            'extension_requested' => 'fas fa-clock text-warning',
            'extension_approved' => 'fas fa-check text-success',
            'extension_rejected' => 'fas fa-times text-danger',
        ];

        return $icons[$this->activity_type] ?? 'fas fa-info-circle text-secondary';
    }

    /**
     * Get priority badge class.
     */
    public function getPriorityBadgeAttribute()
    {
        $badges = [
            'low' => 'badge-secondary',
            'medium' => 'badge-primary',
            'high' => 'badge-warning',
            'critical' => 'badge-danger'
        ];

        return $badges[$this->priority_level] ?? 'badge-secondary';
    }
}
