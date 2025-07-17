<?php

namespace App\Http\Controllers\Dashboard;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class SupervisorDashboardController extends Controller
{
    public function index()
    {
        $companyId = Auth::user()->company_id;

        // Get jobs statistics
        $stats = [
            'total_jobs' => Job::where('company_id', $companyId)->where('active', true)->count(),
            'pending_jobs' => Job::where('company_id', $companyId)->where('status', 'pending')->where('active', true)->count(),
            'in_progress_jobs' => Job::where('company_id', $companyId)->where('status', 'in_progress')->where('active', true)->count(),
            'completed_jobs' => Job::where('company_id', $companyId)->where('status', 'completed')->where('active', true)->count(),
            'total_users' => User::where('company_id', $companyId)->where('active', true)->count(),
            'total_equipment' => Equipment::where('company_id', $companyId)->where('active', true)->count(),
        ];

        // Get recent jobs
        $recentJobs = Job::with(['jobType', 'client', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();

        // Get job types for quick job creation
        $jobTypes = JobType::where('company_id', $companyId)->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        // Get users available for assignment (all active users in company)
        $availableUsers = User::where('company_id', $companyId)
            ->where('active', true)
            ->with('userRole')
            ->get();

        return view('dashboards.supervisor', compact(
            'stats', 'recentJobs', 'jobTypes', 'clients', 'equipments', 'availableUsers'
        ));
    }

    public function getQuickStats()
    {
        $companyId = Auth::user()->company_id;

        $stats = [
            'total_jobs' => Job::where('company_id', $companyId)->where('active', true)->count(),
            'pending_jobs' => Job::where('company_id', $companyId)->where('status', 'pending')->where('active', true)->count(),
            'in_progress_jobs' => Job::where('company_id', $companyId)->where('status', 'in_progress')->where('active', true)->count(),
            'completed_jobs' => Job::where('company_id', $companyId)->where('status', 'completed')->where('active', true)->count(),
            'total_users' => User::where('company_id', $companyId)->where('active', true)->count(),
            'jobs_today' => Job::where('company_id', $companyId)
                ->whereDate('created_at', Carbon::today())
                ->where('active', true)
                ->count(),
        ];

        return response()->json($stats);
    }

    public function getAssignmentUsers()
    {
        $companyId = Auth::user()->company_id;
        
        // Return all active users in the company (removed role restriction)
        $users = User::where('company_id', $companyId)
                    ->where('active', true)
                    ->with('userRole')
                    ->get();

        return response()->json($users);
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

        // Check if user belongs to same company (removed role restriction)
        $user = User::where('id', $request->assigned_user_id)
                   ->where('company_id', $companyId)
                   ->where('active', true)
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
            return response()->json([
                'success' => false,
                'message' => 'Failed to assign jobs: ' . $e->getMessage()
            ], 500);
        }
    }

    public function assignJob(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'user_id' => 'required|exists:users,id',
            'assignment_type' => 'required|in:primary,secondary,supervisor,reviewer',
            'due_date' => 'nullable|date|after_or_equal:today',
            'assignment_notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $assignedUser = User::find($request->user_id);

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

    public function createQuickJob(Request $request)
    {
        $request->validate([
            'job_type_id' => 'required|exists:job_types,id',
            'client_id' => 'nullable|exists:clients,id',
            'equipment_id' => 'nullable|exists:equipments,id',
            'description' => 'required|string|max:1000',
            'priority' => 'required|in:1,2,3,4',
            'assigned_user_id' => 'nullable|exists:users,id',
            'due_date' => 'nullable|date|after_or_equal:today',
        ]);

        try {
            DB::beginTransaction();

            $job = Job::create([
                'company_id' => Auth::user()->company_id,
                'job_type_id' => $request->job_type_id,
                'client_id' => $request->client_id,
                'equipment_id' => $request->equipment_id,
                'description' => $request->description,
                'priority' => $request->priority,
                'assigned_user_id' => $request->assigned_user_id,
                'due_date' => $request->due_date,
                'status' => 'pending',
                'active' => true,
                'created_by' => Auth::id(),
            ]);

            // Log job creation
            \App\Models\Log::create([
                'action' => 'quick_job_created',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Created quick job {$job->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Job created successfully!',
                'job_id' => $job->id,
                'job_url' => route('jobs.show', $job)
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to create job: ' . $e->getMessage()
            ], 500);
        }
    }
}