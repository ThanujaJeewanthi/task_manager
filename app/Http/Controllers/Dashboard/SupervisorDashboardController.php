<?php

namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\Controller;
use App\Models\Job;
use App\Models\Task;
use App\Models\Client;
use App\Models\Employee;
use App\Models\Equipment;
use App\Models\Item;
use App\Models\JobType;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class SupervisorDashboardController extends Controller
{
    public function index()
    {
        $companyId = Auth::user()->company_id;

        // Supervisor-specific statistics
        $stats = [
            'total_jobs' => Job::where('company_id', $companyId)->where('active', true)->count(),
            'jobs_created_by_me' => Job::where('company_id', $companyId)
                ->where('created_by', Auth::id())->where('active', true)->count(),
            'jobs_assigned_to_officers' => Job::where('company_id', $companyId)
                ->whereNotNull('assigned_user_id')->where('active', true)->count(),
            'total_employees' => Employee::where('company_id', $companyId)->where('active', true)->count(),
            'total_clients' => Client::where('company_id', $companyId)->where('active', true)->count(),
            'total_equipment' => Equipment::where('company_id', $companyId)->where('active', true)->count(),
        ];

        // Job status statistics
        $jobStats = [
            'pending_jobs' => Job::where('company_id', $companyId)
                ->where('status', 'pending')->where('active', true)->count(),
            'in_progress_jobs' => Job::where('company_id', $companyId)
                ->where('status', 'in_progress')->where('active', true)->count(),
            'completed_jobs' => Job::where('company_id', $companyId)
                ->where('status', 'completed')->count(),
            'overdue_jobs' => Job::where('company_id', $companyId)
                ->where('due_date', '<', Carbon::now())
                ->whereNotIn('status', ['completed', 'cancelled'])
                ->where('active', true)->count(),
            'high_priority_jobs' => Job::where('company_id', $companyId)
                ->where('priority', 1)
                ->whereNotIn('status', ['completed', 'cancelled'])
                ->where('active', true)->count(),
            'unassigned_jobs' => Job::where('company_id', $companyId)
                ->whereNull('assigned_user_id')
                ->where('active', true)->count(),
        ];

        // Task statistics
        $taskStats = [
            'pending_tasks' => Task::whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })->where('status', 'pending')->where('active', true)->count(),

            'in_progress_tasks' => Task::whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })->where('status', 'in_progress')->where('active', true)->count(),

            'completed_tasks' => Task::whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })->where('status', 'completed')->count(),
        ];

        // Jobs by status for the company
        $jobsByStatus = Job::where('company_id', $companyId)
            ->select('status', DB::raw('count(*) as count'))
            ->where('active', true)
            ->groupBy('status')
            ->get()
            ->pluck('count', 'status');

        // Jobs by priority for the company
        $jobsByPriority = Job::where('company_id', $companyId)
            ->select(
                DB::raw('CASE
                    WHEN priority = 1 THEN "High"
                    WHEN priority = 2 THEN "Medium"
                    WHEN priority = 3 THEN "Low"
                    WHEN priority = 4 THEN "Very Low"
                    ELSE "Unknown"
                END as priority_label'),
                DB::raw('count(*) as count')
            )
            ->where('active', true)
            ->groupBy('priority')
            ->get()
            ->pluck('count', 'priority_label');

        // Jobs created by me
        $myCreatedJobs = Job::with(['jobType', 'client', 'equipment', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('created_by', Auth::id())
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->take(10)
            ->get();

        // Unassigned jobs that need assignment
        $unassignedJobs = Job::with(['jobType', 'client', 'equipment'])
            ->where('company_id', $companyId)
            ->whereNull('assigned_user_id')
            ->where('active', true)
            ->orderBy('priority', 'asc')
            ->orderBy('created_at', 'desc')
            ->take(8)
            ->get();

        // Technical officers available for assignment
        $technicalOfficers = User::where('company_id', $companyId)
            ->whereHas('userRole', function ($query) {
                $query->where('name', 'Technical Officer');
            })
            ->where('active', true)
            ->withCount([
                'assignedJobs as active_jobs_count' => function ($query) {
                    $query->whereNotIn('status', ['completed', 'cancelled'])
                          ->where('active', true);
                }
            ])
            ->get();

        // Equipment status for the company
        $equipmentStats = Equipment::where('company_id', $companyId)
            ->select('status', DB::raw('count(*) as count'))
            ->where('active', true)
            ->groupBy('status')
            ->get()
            ->pluck('count', 'status');

        // Client job distribution
        $clientJobStats = Client::where('company_id', $companyId)
            ->withCount([
                'jobs as total_jobs',
                'jobs as completed_jobs' => function ($query) {
                    $query->where('status', 'completed');
                },
                'jobs as pending_jobs' => function ($query) {
                    $query->where('status', 'pending');
                }
            ])
            ->where('active', true)
            ->orderBy('total_jobs', 'desc')
            ->take(8)
            ->get();

        // Upcoming deadlines (next 7 days)
        $upcomingDeadlines = Job::with(['jobType', 'client', 'equipment', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('due_date', '>=', Carbon::now())
            ->where('due_date', '<=', Carbon::now()->addDays(7))
            ->whereNotIn('status', ['completed', 'cancelled'])
            ->where('active', true)
            ->orderBy('due_date', 'asc')
            ->get();

        // Recent activity on jobs I created
        $recentJobActivity = Job::with(['jobType', 'client', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('created_by', Auth::id())
            ->where('active', true)
            ->orderBy('updated_at', 'desc')
            ->take(8)
            ->get();

        // Jobs by type distribution
        $jobsByType = Job::with('jobType')
            ->where('company_id', $companyId)
            ->join('job_types', 'jobs.job_type_id', '=', 'job_types.id')
            ->select('job_types.name', DB::raw('count(jobs.id) as count'))
            ->where('jobs.active', true)
            ->groupBy('job_types.id', 'job_types.name')
            ->orderBy('count', 'desc')
            ->take(10)
            ->get()
            ->pluck('count', 'name');

        // Monthly job creation trends (last 6 months)
        $monthlyJobTrends = Job::where('company_id', $companyId)
            ->select(
                DB::raw('DATE_FORMAT(created_at, "%Y-%m") as month'),
                DB::raw('count(*) as count')
            )
            ->where('created_at', '>=', Carbon::now()->subMonths(6))
            ->where('active', true)
            ->groupBy('month')
            ->orderBy('month')
            ->get();

        // Supervisor-specific alerts
        $alerts = [];

        if ($jobStats['unassigned_jobs'] > 0) {
            $alerts[] = [
                'type' => 'warning',
                'icon' => 'fas fa-user-slash',
                'message' => "{$jobStats['unassigned_jobs']} jobs need to be assigned to technical officers",
                'count' => $jobStats['unassigned_jobs'],
                'action' => 'Assign Jobs'
            ];
        }

        if ($jobStats['overdue_jobs'] > 0) {
            $alerts[] = [
                'type' => 'danger',
                'icon' => 'fas fa-exclamation-triangle',
                'message' => "{$jobStats['overdue_jobs']} jobs are overdue",
                'count' => $jobStats['overdue_jobs'],
                'action' => 'View Overdue Jobs'
            ];
        }

        $maintenanceEquipment = $equipmentStats['maintenance'] ?? 0;
        if ($maintenanceEquipment > 0) {
            $alerts[] = [
                'type' => 'warning',
                'icon' => 'fas fa-tools',
                'message' => "{$maintenanceEquipment} equipment items need maintenance",
                'count' => $maintenanceEquipment,
                'action' => 'View Equipment'
            ];
        }

        if ($upcomingDeadlines->count() > 0) {
            $alerts[] = [
                'type' => 'info',
                'icon' => 'fas fa-calendar-alt',
                'message' => "{$upcomingDeadlines->count()} jobs due in the next 7 days",
                'count' => $upcomingDeadlines->count(),
                'action' => 'View Upcoming Jobs'
            ];
        }

        if ($jobStats['high_priority_jobs'] > 0) {
            $alerts[] = [
                'type' => 'warning',
                'icon' => 'fas fa-exclamation-circle',
                'message' => "{$jobStats['high_priority_jobs']} high priority jobs need attention",
                'count' => $jobStats['high_priority_jobs'],
                'action' => 'View High Priority Jobs'
            ];
        }

        return view('dashboard.supervisor', compact(
            'stats',
            'jobStats',
            'taskStats',
            'jobsByStatus',
            'jobsByPriority',
            'myCreatedJobs',
            'unassignedJobs',
            'technicalOfficers',
            'equipmentStats',
            'clientJobStats',
            'upcomingDeadlines',
            'recentJobActivity',
            'jobsByType',
            'monthlyJobTrends',
            'alerts'
        ));
    }

     public function assignJob(Request $request, Job $job)
    {
        $request->validate([
            'user_id' => 'required|exists:users,id',
            'assignment_type' => 'required|in:primary,secondary,supervisor,reviewer',
            'due_date' => 'nullable|date',
            'assignment_notes' => 'nullable|string|max:500',
        ]);

        try {
            DB::beginTransaction();

            // Check company access
            if ($job->company_id !== Auth::user()->company_id) {
                abort(403);
            }

            $assignedUser = \App\Models\User::find($request->user_id);

            // Create job assignment
            $assignment = $job->assignments()->create([
                'user_id' => $request->user_id,
                'assigned_by' => Auth::id(),
                'assignment_type' => $request->assignment_type,
                'due_date' => $request->due_date,
                'assignment_notes' => $request->assignment_notes,
                'status' => 'assigned',
                'created_by' => Auth::id(),
                'updated_by' => Auth::id(),
            ]);

            // Update job assigned_user_id if primary assignment
            if ($request->assignment_type === 'primary') {
                $job->update([
                    'assigned_user_id' => $request->user_id,
                    'updated_by' => Auth::id(),
                ]);
            }

            // Log job assignment
            JobActivityLogger::logJobAssigned($job, $assignedUser, $request->assignment_type);

            DB::commit();

            return redirect()->route('jobs.show', $job)
                ->with('success', 'Job assigned successfully!');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()
                ->with('error', 'Failed to assign job. Please try again.');
        }
    }
    public function bulkAssignJobs(Request $request)
    {
        $request->validate([
            'job_ids' => 'required|array',
            'job_ids.*' => 'exists:jobs,id',
            'assigned_user_id' => 'required|exists:users,id',
            'priority' => 'required|in:1,2,3,4',
        ]);

        $companyId = Auth::user()->company_id;

        // Check if user belongs to same company and has Technical Officer role
        $user = User::where('id', $request->assigned_user_id)
                   ->where('company_id', $companyId)
                   ->whereHas('userRole', function ($query) {
                       $query->where('name', 'Technical Officer');
                   })
                   ->firstOrFail();

        try {
            DB::beginTransaction();

            Job::whereIn('id', $request->job_ids)
               ->where('company_id', $companyId)
               ->update([
                   'assigned_user_id' => $request->assigned_user_id,
                   'priority' => $request->priority,
                   'status' => 'pending',
                   'updated_by' => Auth::id(),
               ]);

            // Log the bulk assignment
            \App\Models\Log::create([
                'action' => 'bulk_job_assignment',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Bulk assigned " . count($request->job_ids) . " jobs to {$user->name}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => count($request->job_ids) . " jobs assigned to {$user->name} successfully!"
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['error' => 'Failed to assign jobs'], 500);
        }
    }

    public function getQuickStats()
    {
        $companyId = Auth::user()->company_id;

        return response()->json([
            'total_jobs' => Job::where('company_id', $companyId)->where('active', true)->count(),
            'unassigned_jobs' => Job::where('company_id', $companyId)
                ->whereNull('assigned_user_id')->where('active', true)->count(),
            'overdue_jobs' => Job::where('company_id', $companyId)
                ->where('due_date', '<', Carbon::now())
                ->whereNotIn('status', ['completed', 'cancelled'])
                ->where('active', true)->count(),
            'jobs_created_by_me' => Job::where('company_id', $companyId)
                ->where('created_by', Auth::id())->where('active', true)->count(),
        ]);
    }

    public function getJobAssignmentData(Request $request)
    {
        $companyId = Auth::user()->company_id;

        $unassignedJobs = Job::with(['jobType', 'client'])
            ->where('company_id', $companyId)
            ->whereNull('assigned_user_id')
            ->where('active', true)
            ->get();

        $technicalOfficers = User::where('company_id', $companyId)
            ->whereHas('userRole', function ($query) {
                $query->where('name', 'Technical Officer');
            })
            ->where('active', true)
            ->withCount([
                'assignedJobs as active_jobs_count' => function ($query) {
                    $query->whereNotIn('status', ['completed', 'cancelled'])
                          ->where('active', true);
                }
            ])
            ->get();

        return response()->json([
            'unassigned_jobs' => $unassignedJobs,
            'technical_officers' => $technicalOfficers
        ]);
    }
}

