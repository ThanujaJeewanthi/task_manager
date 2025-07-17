<?php
namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\Controller;
use App\Models\Job;
use App\Models\Task;
use App\Models\Equipment;
use App\Models\Item;
use App\Models\User;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class TechnicalOfficerDashboardController extends Controller
{
    public function index()
    {
        $companyId = Auth::user()->company_id;

        // Get assigned jobs for this user (removed role-specific filtering)
        $assignedJobs = Job::where('company_id', $companyId)
            ->where('assigned_user_id', Auth::id())
            ->where('active', true);

        $stats = [
            'my_assigned_jobs' => $assignedJobs->count(),
            'my_pending_jobs' => $assignedJobs->where('status', 'pending')->count(),
            'my_in_progress_jobs' => $assignedJobs->where('status', 'in_progress')->count(),
            'my_completed_jobs' => $assignedJobs->where('status', 'completed')->count(),
            'jobs_awaiting_approval' => Job::where('company_id', $companyId)
                ->where('approval_status', 'requested')
                ->where('created_by', Auth::id())
                ->where('active', true)->count(),
            'total_equipment' => Equipment::where('company_id', $companyId)->where('active', true)->count(),
        ];

        // Get tasks assigned to this user
        $myTasks = JobEmployee::where('user_id', Auth::id())
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId)->where('active', true);
            })
            ->with(['job', 'task'])
            ->get();

        $taskStats = [
            'total_tasks' => $myTasks->count(),
            'pending_tasks' => $myTasks->where('status', 'pending')->count(),
            'in_progress_tasks' => $myTasks->where('status', 'in_progress')->count(),
            'completed_tasks' => $myTasks->where('status', 'completed')->count(),
        ];

        // Performance metrics for this user
        $performanceStats = [
            'jobs_completed_this_week' => Job::where('company_id', $companyId)
                ->where('assigned_user_id', Auth::id())
                ->where('status', 'completed')
                ->whereBetween('completed_date', [Carbon::now()->startOfWeek(), Carbon::now()->endOfWeek()])
                ->count(),
            'jobs_completed_this_month' => Job::where('company_id', $companyId)
                ->where('assigned_user_id', Auth::id())
                ->where('status', 'completed')
                ->whereMonth('completed_date', Carbon::now()->month)
                ->whereYear('completed_date', Carbon::now()->year)
                ->count(),
            'tasks_completed_this_week' => JobEmployee::where('user_id', Auth::id())
                ->where('status', 'completed')
                ->whereBetween('updated_at', [Carbon::now()->startOfWeek(), Carbon::now()->endOfWeek()])
                ->count(),
            'average_completion_time' => $this->getAverageCompletionTime(Auth::id(), $companyId),
        ];

        // Recent assigned jobs
        $recentJobs = Job::with(['jobType', 'client', 'equipment'])
            ->where('company_id', $companyId)
            ->where('assigned_user_id', Auth::id())
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        // Recent tasks
        $recentTasks = $myTasks->sortByDesc('created_at')->take(10);

        // Pending approvals that this user requested
        $pendingApprovals = Job::with(['jobType', 'client'])
            ->where('company_id', $companyId)
            ->where('approval_status', 'requested')
            ->where('created_by', Auth::id())
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->get();

        return view('dashboards.technical-officer', compact(
            'stats', 'taskStats', 'performanceStats', 'recentJobs', 'recentTasks', 'pendingApprovals'
        ));
    }

    public function getQuickStats()
    {
        $companyId = Auth::user()->company_id;
        
        $stats = [
            'pending_jobs' => Job::where('company_id', $companyId)
                ->where('assigned_user_id', Auth::id())
                ->where('status', 'pending')
                ->where('active', true)
                ->count(),
            'in_progress_jobs' => Job::where('company_id', $companyId)
                ->where('assigned_user_id', Auth::id())
                ->where('status', 'in_progress')
                ->where('active', true)
                ->count(),
            'awaiting_approval' => Job::where('company_id', $companyId)
                ->where('approval_status', 'requested')
                ->where('created_by', Auth::id())
                ->where('active', true)
                ->count(),
            'my_tasks' => JobEmployee::where('user_id', Auth::id())
                ->whereHas('job', function ($query) use ($companyId) {
                    $query->where('company_id', $companyId)->where('active', true);
                })
                ->where('status', '!=', 'completed')
                ->count(),
        ];

        return response()->json($stats);
    }

    public function completeJob(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id || $job->assigned_user_id !== Auth::id()) {
            abort(403);
        }

        $request->validate([
            'completion_notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $job->update([
                'status' => 'completed',
                'completed_date' => now(),
                'approval_notes' => $request->completion_notes,
                'updated_by' => Auth::id(),
            ]);

            // Log job completion
            \App\Models\Log::create([
                'action' => 'job_completed',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Completed job {$job->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Job completed successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to complete job: ' . $e->getMessage()
            ], 500);
        }
    }

    public function updateJobStatus(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id || $job->assigned_user_id !== Auth::id()) {
            abort(403);
        }

        $request->validate([
            'status' => 'required|in:pending,in_progress,on_hold,completed,cancelled',
            'notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $updateData = [
                'status' => $request->status,
                'updated_by' => Auth::id(),
            ];

            if ($request->status === 'completed') {
                $updateData['completed_date'] = now();
            }

            if ($request->notes) {
                $updateData['approval_notes'] = $request->notes;
            }

            $job->update($updateData);

            // Log status change
            \App\Models\Log::create([
                'action' => 'job_status_updated',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Updated job {$job->id} status to {$request->status}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Job status updated successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to update job status: ' . $e->getMessage()
            ], 500);
        }
    }

    public function updateTaskStatus(Request $request, Task $task)
    {
        $request->validate([
            'status' => 'required|in:pending,in_progress,completed,cancelled',
            'notes' => 'nullable|string|max:1000',
        ]);

    public function updateTaskStatus(Request $request, Task $task)
    {
        $request->validate([
            'status' => 'required|in:pending,in_progress,completed,cancelled',
            'notes' => 'nullable|string|max:1000',
        ]);

        // Check if user is assigned to this task
        $taskAssignment = JobEmployee::where('user_id', Auth::id())
            ->where('task_id', $task->id)
            ->whereHas('job', function ($query) {
                $query->where('company_id', Auth::user()->company_id);
            })
            ->first();

        if (!$taskAssignment) {
            abort(403);
        }

        try {
            DB::beginTransaction();

            $taskAssignment->update([
                'status' => $request->status,
                'notes' => $request->notes,
                'updated_by' => Auth::id(),
            ]);

            // Log task status change
            \App\Models\Log::create([
                'action' => 'task_status_updated',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Updated task {$task->id} status to {$request->status}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Task status updated successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to update task status: ' . $e->getMessage()
            ], 500);
        }
    }

    public function requestApproval(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id || $job->assigned_user_id !== Auth::id()) {
            abort(403);
        }

        $request->validate([
            'approval_notes' => 'required|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $job->update([
                'approval_status' => 'requested',
                'approval_notes' => $request->approval_notes,
                'updated_by' => Auth::id(),
            ]);

            // Log approval request
            \App\Models\Log::create([
                'action' => 'approval_requested',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Requested approval for job {$job->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Approval requested successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to request approval: ' . $e->getMessage()
            ], 500);
        }
    }

    private function getAverageCompletionTime($userId, $companyId)
    {
        $completedJobs = Job::where('company_id', $companyId)
            ->where('assigned_user_id', $userId)
            ->where('status', 'completed')
            ->whereNotNull('start_date')
            ->whereNotNull('completed_date')
            ->get();

        if ($completedJobs->isEmpty()) {
            return 0;
        }

        $totalDays = 0;
        foreach ($completedJobs as $job) {
            $startDate = Carbon::parse($job->start_date);
            $completedDate = Carbon::parse($job->completed_date);
            $totalDays += $startDate->diffInDays($completedDate);
        }

        return round($totalDays / $completedJobs->count(), 1);
    }
}
