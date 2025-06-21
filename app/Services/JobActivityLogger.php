<?php

namespace App\Services;

use App\Models\JobActivityLog;
use App\Models\Job;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Request;

class JobActivityLogger
{
    /**
     * Log a job-related activity.
     */
    public static function log(array $params)
    {
        $user = Auth::user();
        $userAgent = Request::header('User-Agent');

        // Extract browser info
        $browserInfo = self::extractBrowserInfo($userAgent);

        return JobActivityLog::create([
            'job_id' => $params['job_id'],
            'activity_type' => $params['activity_type'],
            'activity_category' => $params['activity_category'] ?? 'job',
            'priority_level' => $params['priority_level'] ?? 'medium',
            'is_major_activity' => $params['is_major_activity'] ?? false,
            'user_id' => $user?->id,
            'user_role' => $user?->userRole?->name,
            'ip_address' => Request::ip(),
            'description' => $params['description'],
            'old_values' => $params['old_values'] ?? null,
            'new_values' => $params['new_values'] ?? null,
            'metadata' => $params['metadata'] ?? null,
            'related_model_type' => $params['related_model_type'] ?? null,
            'related_model_id' => $params['related_model_id'] ?? null,
            'related_entity_name' => $params['related_entity_name'] ?? null,
            'affected_user_id' => $params['affected_user_id'] ?? null,
            'browser_info' => $browserInfo,
            'created_by' => $user?->id,
            'updated_by' => $user?->id,
        ]);
    }

    /**
     * Log job creation.
     */
    public static function logJobCreated(Job $job, array $additionalData = [])
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'created',
            'activity_category' => 'job',
            'priority_level' => 'high',
            'is_major_activity' => true,
            'description' => "Job '{$job->description}' was created with priority {$job->priority}",
            'new_values' => [
                'job_type' => $job->jobType?->name,
                'client' => $job->client?->name,
                'equipment' => $job->equipment?->name,
                'priority' => $job->priority,
                'status' => $job->status,
                'description' => $job->description,
            ],
            'metadata' => array_merge([
                'job_type_id' => $job->job_type_id,
                'client_id' => $job->client_id,
                'equipment_id' => $job->equipment_id,
            ], $additionalData),
        ]);
    }

    /**
     * Log job assignment.
     */
    public static function logJobAssigned(Job $job, $assignedUser, $assignmentType = 'primary')
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'assigned',
            'activity_category' => 'assignment',
            'priority_level' => 'high',
            'is_major_activity' => true,
            'description' => "Job assigned to {$assignedUser->name} as {$assignmentType}",
            'affected_user_id' => $assignedUser->id,
            'new_values' => [
                'assigned_to' => $assignedUser->name,
                'assignment_type' => $assignmentType,
                'assigned_at' => now(),
            ],
            'metadata' => [
                'assignment_type' => $assignmentType,
                'assigned_user_role' => $assignedUser->userRole?->name,
            ],
        ]);
    }

    /**
     * Log job status change.
     */
    public static function logJobStatusChanged(Job $job, $oldStatus, $newStatus, $notes = null)
    {
        $isMajor = in_array($newStatus, ['completed', 'cancelled', 'approved']);
        $priority = $isMajor ? 'high' : 'medium';

        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'status_changed',
            'activity_category' => 'job',
            'priority_level' => $priority,
            'is_major_activity' => $isMajor,
            'description' => "Job status changed from '{$oldStatus}' to '{$newStatus}'" . ($notes ? " - {$notes}" : ''),
            'old_values' => ['status' => $oldStatus],
            'new_values' => ['status' => $newStatus],
            'metadata' => [
                'notes' => $notes,
                'status_change_reason' => $notes,
            ],
        ]);
    }

    /**
     * Log job approval/rejection.
     */
    public static function logJobApproval(Job $job, $action, $notes = null, $approver = null)
    {
        $approver = $approver ?: Auth::user();

        return self::log([
            'job_id' => $job->id,
            'activity_type' => $action, // 'approved' or 'rejected'
            'activity_category' => 'approval',
            'priority_level' => 'critical',
            'is_major_activity' => true,
            'description' => "Job {$action} by {$approver->name}" . ($notes ? " - {$notes}" : ''),
            'new_values' => [
                'approval_status' => $action,
                'approver' => $approver->name,
                'approval_notes' => $notes,
                'approved_at' => now(),
            ],
            'metadata' => [
                'approver_role' => $approver->userRole?->name,
                'approval_notes' => $notes,
            ],
        ]);
    }

    /**
     * Log item addition to job.
     */
    public static function logItemAdded(Job $job, $itemData, $quantity, $notes = null)
    {
        $itemName = $itemData['name'] ?? $itemData['custom_item_description'] ?? 'Unknown Item';

        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'item_added',
            'activity_category' => 'item',
            'priority_level' => 'medium',
            'is_major_activity' => true,
            'description' => "Added item '{$itemName}' (Qty: {$quantity})" . ($notes ? " - {$notes}" : ''),
            'new_values' => [
                'item_name' => $itemName,
                'quantity' => $quantity,
                'notes' => $notes,
            ],
            'related_model_type' => 'JobItem',
            'related_model_id' => $itemData['id'] ?? null,
            'related_entity_name' => $itemName,
            'metadata' => [
                'item_type' => isset($itemData['id']) ? 'existing' : 'custom',
                'quantity' => $quantity,
                'notes' => $notes,
            ],
        ]);
    }

    /**
     * Log item quantity update.
     */
    public static function logItemUpdated(Job $job, $itemData, $oldQuantity, $newQuantity, $notes = null)
    {
        $itemName = $itemData['name'] ?? $itemData['custom_item_description'] ?? 'Unknown Item';

        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'item_updated',
            'activity_category' => 'item',
            'priority_level' => 'medium',
            'is_major_activity' => false,
            'description' => "Updated item '{$itemName}' quantity from {$oldQuantity} to {$newQuantity}" . ($notes ? " - {$notes}" : ''),
            'old_values' => [
                'quantity' => $oldQuantity,
            ],
            'new_values' => [
                'quantity' => $newQuantity,
                'notes' => $notes,
            ],
            'related_model_type' => 'JobItem',
            'related_model_id' => $itemData['id'] ?? null,
            'related_entity_name' => $itemName,
        ]);
    }

    /**
     * Log task creation.
     */
    public static function logTaskCreated(Job $job, $task, $assignedEmployees = [])
    {
        $employeeNames = collect($assignedEmployees)->pluck('name')->join(', ');

        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'task_created',
            'activity_category' => 'task',
            'priority_level' => 'medium',
            'is_major_activity' => true,
            'description' => "Created task '{$task->task}'" .
                ($employeeNames ? " and assigned to: {$employeeNames}" : ''),
            'new_values' => [
                'task_name' => $task->task,
                'task_description' => $task->description,
                'assigned_employees' => $employeeNames,
            ],
            'related_model_type' => 'Task',
            'related_model_id' => $task->id,
            'related_entity_name' => $task->task,
            'metadata' => [
                'assigned_employee_count' => count($assignedEmployees),
                'employee_ids' => collect($assignedEmployees)->pluck('id')->toArray(),
            ],
        ]);
    }

    /**
     * Log task assignment to employee.
     */
    public static function logTaskAssigned(Job $job, $task, $employee, $startDate = null, $endDate = null)
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'task_assigned',
            'activity_category' => 'task',
            'priority_level' => 'medium',
            'is_major_activity' => false,
            'description' => "Assigned task '{$task->task}' to {$employee->user->name}" .
                ($startDate && $endDate ? " ({$startDate} to {$endDate})" : ''),
            'affected_user_id' => $employee->user_id,
            'new_values' => [
                'task_name' => $task->task,
                'assigned_to' => $employee->user->name,
                'start_date' => $startDate,
                'end_date' => $endDate,
            ],
            'related_model_type' => 'Task',
            'related_model_id' => $task->id,
            'related_entity_name' => $task->task,
        ]);
    }

    /**
     * Log task extension request.
     */
    public static function logTaskExtensionRequested(Job $job, $task, $employee, $currentEndDate, $requestedEndDate, $reason)
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'extension_requested',
            'activity_category' => 'task',
            'priority_level' => 'medium',
            'is_major_activity' => false,
            'description' => "Extension requested for task '{$task->task}' by {$employee->user->name} from {$currentEndDate} to {$requestedEndDate}",
            'affected_user_id' => $employee->user_id,
            'old_values' => ['end_date' => $currentEndDate],
            'new_values' => ['requested_end_date' => $requestedEndDate],
            'related_model_type' => 'Task',
            'related_model_id' => $task->id,
            'related_entity_name' => $task->task,
            'metadata' => [
                'reason' => $reason,
                'extension_days' => \Carbon\Carbon::parse($requestedEndDate)->diffInDays(\Carbon\Carbon::parse($currentEndDate)),
            ],
        ]);
    }

    /**
     * Log task extension approval/rejection.
     */
    public static function logTaskExtensionProcessed(Job $job, $task, $employee, $action, $notes = null)
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => "extension_{$action}", // extension_approved or extension_rejected
            'activity_category' => 'task',
            'priority_level' => 'medium',
            'is_major_activity' => true,
            'description' => "Task extension {$action} for '{$task->task}' assigned to {$employee->user->name}" .
                ($notes ? " - {$notes}" : ''),
            'affected_user_id' => $employee->user_id,
            'new_values' => [
                'extension_status' => $action,
                'review_notes' => $notes,
            ],
            'related_model_type' => 'Task',
            'related_model_id' => $task->id,
            'related_entity_name' => $task->task,
            'metadata' => [
                'review_notes' => $notes,
            ],
        ]);
    }

    /**
     * Log task completion.
     */
    public static function logTaskCompleted(Job $job, $task, $employee, $completionNotes = null)
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'completed',
            'activity_category' => 'task',
            'priority_level' => 'high',
            'is_major_activity' => true,
            'description' => "Task '{$task->task}' completed by {$employee->user->name}" .
                ($completionNotes ? " - {$completionNotes}" : ''),
            'affected_user_id' => $employee->user_id,
            'new_values' => [
                'completed_by' => $employee->user->name,
                'completed_at' => now(),
                'completion_notes' => $completionNotes,
            ],
            'related_model_type' => 'Task',
            'related_model_id' => $task->id,
            'related_entity_name' => $task->task,
        ]);
    }

    /**
     * Log job completion.
     */
    public static function logJobCompleted(Job $job, $completionNotes = null)
    {
        return self::log([
            'job_id' => $job->id,
            'activity_type' => 'completed',
            'activity_category' => 'job',
            'priority_level' => 'critical',
            'is_major_activity' => true,
            'description' => "Job completed" . ($completionNotes ? " - {$completionNotes}" : ''),
            'new_values' => [
                'completed_at' => now(),
                'completion_notes' => $completionNotes,
                'final_status' => 'completed',
            ],
            'metadata' => [
                'completion_notes' => $completionNotes,
            ],
        ]);
    }

    /**
     * Extract browser information from user agent.
     */
    private static function extractBrowserInfo($userAgent)
    {
        if (!$userAgent) {
            return null;
        }

        // Simple browser detection
        $browsers = [
            'Chrome' => '/Chrome\/([0-9.]+)/',
            'Firefox' => '/Firefox\/([0-9.]+)/',
            'Safari' => '/Safari\/([0-9.]+)/',
            'Edge' => '/Edge\/([0-9.]+)/',
            'Opera' => '/Opera\/([0-9.]+)/',
        ];

        foreach ($browsers as $browser => $pattern) {
            if (preg_match($pattern, $userAgent, $matches)) {
                return "{$browser} {$matches[1]}";
            }
        }

        return 'Unknown Browser';
    }

    /**
     * Get activity timeline for a job.
     */
    public static function getJobTimeline($jobId, $majorOnly = false)
    {
        $query = JobActivityLog::where('job_id', $jobId)
            ->with(['user', 'affectedUser'])
            ->orderBy('created_at', 'desc');

        if ($majorOnly) {
            $query->majorActivities();
        }

        return $query->get();
    }

    /**
     * Get activity statistics for a job.
     */
    public static function getJobActivityStats($jobId)
    {
        return [
            'total_activities' => JobActivityLog::where('job_id', $jobId)->count(),
            'major_activities' => JobActivityLog::where('job_id', $jobId)->majorActivities()->count(),
            'users_involved' => JobActivityLog::where('job_id', $jobId)->distinct('user_id')->count('user_id'),
            'last_activity' => JobActivityLog::where('job_id', $jobId)->latest()->first()?->created_at,
            'activity_by_category' => JobActivityLog::where('job_id', $jobId)
                ->selectRaw('activity_category, COUNT(*) as count')
                ->groupBy('activity_category')
                ->pluck('count', 'activity_category'),
        ];
    }
}
