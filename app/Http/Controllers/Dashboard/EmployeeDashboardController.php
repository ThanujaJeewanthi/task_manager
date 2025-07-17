<?php


namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\Controller;
use App\Models\Job;
use App\Models\Task;
use App\Models\User;
use App\Models\Equipment;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class EngineerDashboardController extends Controller
{
    public function index()
    {
        $companyId = Auth::user()->company_id;

        // Get general company statistics
        $stats = [
            'total_jobs' => Job::where('company_id', $companyId)->where('active', true)->count(),
            'pending_jobs' => Job::where('company_id', $companyId)->where('status', 'pending')->where('active', true)->count(),
            'in_progress_jobs' => Job::where('company_id', $companyId)->where('status', 'in_progress')->where('active', true)->count(),
            'completed_jobs' => Job::where('company_id', $companyId)->where('status', 'completed')->where('active', true)->count(),
            'jobs_awaiting_approval' => Job::where('company_id', $companyId)->where('approval_status', 'requested')->where('active', true)->count(),
            'total_users' => User::where('company_id', $companyId)->where('active', true)->count(),
            'total_equipment' => Equipment::where('company_id', $companyId)->where('active', true)->count(),
        ];

        // Get jobs assigned to this engineer
        $myJobs = Job::where('company_id', $companyId)
            ->where('assigned_user_id', Auth::id())
            ->where('active', true);

        $myJobStats = [
            'my_assigned_jobs' => $myJobs->count(),
            'my_pending_jobs' => $myJobs->where('status', 'pending')->count(),
            'my_in_progress_jobs' => $myJobs->where('status', 'in_progress')->count(),
            'my_completed_jobs' => $myJobs->where('status', 'completed')->count(),
        ];

        // Get tasks assigned to this engineer
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

        // Recent jobs awaiting approval
        $pendingApprovals = Job::with(['jobType', 'client', 'creator'])
            ->where('company_id', $companyId)
            ->where('approval_status', 'requested')
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        // Recent jobs
        $recentJobs = Job::with(['jobType', 'client', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        // Performance metrics
        $performanceStats = [
            'jobs_completed_this_week' => Job::where('company_id', $companyId)
                ->where('status', 'completed')
                ->whereBetween('completed_date', [Carbon::now()->startOfWeek(), Carbon::now()->endOfWeek()])
                ->count(),
            'jobs_completed_this_month' => Job::where('company_id', $companyId)
                ->where('status', 'completed')
                ->whereMonth('completed_date', Carbon::now()->month)
                ->whereYear('completed_date', Carbon::now()->year)
                ->count(),
            'approval_rate' => $this->getApprovalRate($companyId),
        ];

        return view('dashboards.engineer', compact(
            'stats', 'myJobStats', 'taskStats', 'pendingApprovals', 'recentJobs', 'performanceStats'
        ));
    }

    public function getQuickStats()
    {
        $companyId = Auth::user()->company_id;

        $stats = [
            'pending_approvals' => Job::where('company_id', $companyId)
                ->where('approval_status', 'requested')
                ->where('active', true)
                ->count(),
            'my_assigned_jobs' => Job::where('company_id', $companyId)
                ->where('assigned_user_id', Auth::id())
                ->where('active', true)
                ->count(),
            'my_pending_tasks' => JobEmployee::where('user_id', Auth::id())
                ->whereHas('job', function ($query) use ($companyId) {
                    $query->where('company_id', $companyId)->where('active', true);
                })
                ->where('status', 'pending')
                ->count(),
            'total_active_jobs' => Job::where('company_id', $companyId)
                ->where('active', true)
                ->whereIn('status', ['pending', 'in_progress'])
                ->count(),
        ];

        return response()->json($stats);
    }

    public function approveJob(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'action' => 'required|in:approve,reject',
            'notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            if ($request->action === 'approve') {
                $job->update([
                    'approval_status' => 'approved',
                    'approved_by' => Auth::id(),
                    'approved_at' => now(),
                    'approval_notes' => $request->notes,
                    'updated_by' => Auth::id(),
                ]);

                $message = 'Job approved successfully!';
            } else {
                $job->update([
                    'approval_status' => 'rejected',
                    'rejected_by' => Auth::id(),
                    'rejected_at' => now(),
                    'rejection_notes' => $request->notes,
                    'updated_by' => Auth::id(),
                ]);

                $message = 'Job rejected successfully!';
            }

            // Log the action
            \App\Models\Log::create([
                'action' => 'job_' . $request->action . 'd',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => ucfirst($request->action) . "d job {$job->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => $message
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to ' . $request->action . ' job: ' . $e->getMessage()
            ], 500);
        }
    }

    public function bulkApproveJobs(Request $request)
    {
        $request->validate([
            'job_ids' => 'required|array',
            'job_ids.*' => 'exists:jobs,id',
            'action' => 'required|in:approve,reject',
            'notes' => 'nullable|string|max:1000',
        ]);

        $companyId = Auth::user()->company_id;

        try {
            DB::beginTransaction();

            $jobs = Job::whereIn('id', $request->job_ids)
                      ->where('company_id', $companyId)
                      ->where('approval_status', 'requested')
                      ->get();

            if ($jobs->isEmpty()) {
                return response()->json([
                    'success' => false,
                    'message' => 'No jobs found for approval.'
                ], 404);
            }

            foreach ($jobs as $job) {
                if ($request->action === 'approve') {
                    $job->update([
                        'approval_status' => 'approved',
                        'approved_by' => Auth::id(),
                        'approved_at' => now(),
                        'approval_notes' => $request->notes,
                        'updated_by' => Auth::id(),
                    ]);
                } else {
                    $job->update([
                        'approval_status' => 'rejected',
                        'rejected_by' => Auth::id(),
                        'rejected_at' => now(),
                        'rejection_notes' => $request->notes,
                        'updated_by' => Auth::id(),
                    ]);
                }
            }

            // Log bulk action
            \App\Models\Log::create([
                'action' => 'bulk_job_' . $request->action,
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Bulk " . $request->action . "d " . $jobs->count() . " jobs",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => $jobs->count() . ' jobs ' . $request->action . 'd successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to ' . $request->action . ' jobs: ' . $e->getMessage()
            ], 500);
        }
    }

    public function getNotificationCounts()
    {
        $companyId = Auth::user()->company_id;

        $counts = [
            'pending_approvals' => Job::where('company_id', $companyId)
                ->where('approval_status', 'requested')
                ->where('active', true)
                ->count(),
            'overdue_jobs' => Job::where('company_id', $companyId)
                ->where('due_date', '<', now())
                ->whereIn('status', ['pending', 'in_progress'])
                ->where('active', true)
                ->count(),
            'high_priority_jobs' => Job::where('company_id', $companyId)
                ->where('priority', '1')
                ->whereIn('status', ['pending', 'in_progress'])
                ->where('active', true)
                ->count(),
        ];

        return response()->json($counts);
    }

    private function getApprovalRate($companyId)
    {
        $totalApprovals = Job::where('company_id', $companyId)
            ->whereIn('approval_status', ['approved', 'rejected'])
            ->count();

        if ($totalApprovals === 0) {
            return 0;
        }

        $approvedCount = Job::where('company_id', $companyId)
            ->where('approval_status', 'approved')
            ->count();

        return round(($approvedCount / $totalApprovals) * 100, 1);
    }
}
