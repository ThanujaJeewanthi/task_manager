<?php

namespace App\Http\Controllers\Job;

use App\Http\Controllers\Controller;
use App\Models\Job;
use App\Models\JobAssignment;
use App\Models\User;
use App\Services\JobActivityLogger;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class JobAssignmentController extends Controller
{
    public function index()
    {
        $companyId = Auth::user()->company_id;
        
        $assignments = JobAssignment::with(['job.jobType', 'user.userRole', 'assignedBy'])
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->paginate(15);

        return view('job-assignments.index', compact('assignments'));
    }

    public function create(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Get all users from same company (removed role restriction)
        $users = User::where('company_id', Auth::user()->company_id)
                    ->where('active', true)
                    ->with('userRole')
                    ->get();

        return view('job-assignments.create', compact('job', 'users'));
    }

    public function store(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'user_id' => 'required|exists:users,id',
            'assignment_type' => 'required|in:primary,secondary,supervisor,reviewer',
            'due_date' => 'nullable|date|after_or_equal:today',
            'assignment_notes' => 'nullable|string|max:1000',
            'can_assign_tasks' => 'boolean'
        ]);

        // Check if user belongs to same company
        $user = User::where('id', $request->user_id)
                   ->where('company_id', Auth::user()->company_id)
                   ->firstOrFail();

        // Check if primary assignment already exists
        if ($request->assignment_type === 'primary') {
            $existingPrimary = JobAssignment::where('job_id', $job->id)
                                          ->where('assignment_type', 'primary')
                                          ->where('active', true)
                                          ->first();

            if ($existingPrimary) {
                return back()->withErrors(['assignment_type' => 'This job already has a primary assignee.']);
            }
        }

        // Check if user is already assigned to this job
        $existingAssignment = JobAssignment::where('job_id', $job->id)
                                         ->where('user_id', $request->user_id)
                                         ->where('active', true)
                                         ->first();

        if ($existingAssignment) {
            return back()->withErrors(['user_id' => 'This user is already assigned to this job.']);
        }

        try {
            DB::beginTransaction();

            $assignment = $job->assignToUser($request->user_id, $request->assignment_type, [
                'due_date' => $request->due_date,
                'assignment_notes' => $request->assignment_notes,
                'can_assign_tasks' => $request->boolean('can_assign_tasks', $request->assignment_type === 'primary')
            ]);

            // Log the assignment
            \App\Models\Log::create([
                'action' => 'job_assigned',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Assigned job {$job->id} to {$user->name} as {$request->assignment_type}",
                'active' => true
            ]);

            JobActivityLogger::logJobAssigned($job, $user, $request->assignment_type);
            
            DB::commit();

            return redirect()->route('jobs.show', $job)
                           ->with('success', "Job assigned to {$user->name} successfully!");

        } catch (\Exception $e) {
            DB::rollBack();
            return back()->withErrors(['error' => 'Failed to assign job: ' . $e->getMessage()]);
        }
    }

    public function show(JobAssignment $assignment)
    {
        if ($assignment->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $assignment->load(['job.jobType', 'user.userRole', 'assignedBy']);
        return view('job-assignments.show', compact('assignment'));
    }

    public function updateStatus(Request $request, JobAssignment $assignment)
    {
        if ($assignment->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'status' => 'required|in:assigned,accepted,in_progress,completed,rejected',
            'notes' => 'nullable|string|max:1000'
        ]);

        try {
            DB::beginTransaction();

            $assignment->update([
                'status' => $request->status,
                'notes' => $request->notes,
                'updated_by' => Auth::id()
            ]);

            // Log status update
            \App\Models\Log::create([
                'action' => 'job_assignment_status_updated',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Updated job assignment {$assignment->id} status to {$request->status}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->back()->with('success', 'Assignment status updated successfully!');

        } catch (\Exception $e) {
            DB::rollBack();
            return back()->withErrors(['error' => 'Failed to update status: ' . $e->getMessage()]);
        }
    }

    public function destroy(JobAssignment $assignment)
    {
        if ($assignment->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        try {
            DB::beginTransaction();

            $assignment->update([
                'active' => false,
                'updated_by' => Auth::id()
            ]);

            // Log assignment removal
            \App\Models\Log::create([
                'action' => 'job_assignment_removed',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => request()->ip(),
                'description' => "Removed job assignment {$assignment->id}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->route('job-assignments.index')
                           ->with('success', 'Job assignment removed successfully!');

        } catch (\Exception $e) {
            DB::rollBack();
            return back()->withErrors(['error' => 'Failed to remove assignment: ' . $e->getMessage()]);
        }
    }

    public function myAssignments()
    {
        $companyId = Auth::user()->company_id;
        
        $assignments = JobAssignment::with(['job.jobType', 'job.client', 'assignedBy'])
            ->where('user_id', Auth::id())
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId)->where('active', true);
            })
            ->where('active', true)
            ->orderBy('created_at', 'desc')
            ->paginate(15);

        return view('job-assignments.my-assignments', compact('assignments'));
    }
}