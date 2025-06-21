<?php

namespace App\Http\Controllers\Job;

use App\Models\Job;
use App\Models\User;
use App\Models\UserRole;
use Illuminate\Http\Request;
use App\Models\JobAssignment;
use Illuminate\Support\Facades\DB;
use App\Services\JobActivityLogger;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;

class JobAssignmentController extends Controller
{
    public function index(Request $request)
    {
        $companyId = Auth::user()->company_id;

        $query = JobAssignment::with(['job.jobType', 'job.client', 'user.userRole'])
                             ->whereHas('job', function($q) use ($companyId) {
                                 $q->where('company_id', $companyId);
                             })
                             ->where('active', true);

        // Apply filters
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }

        if ($request->filled('assignment_type')) {
            $query->where('assignment_type', $request->assignment_type);
        }

        if ($request->filled('user_id')) {
            $query->where('user_id', $request->user_id);
        }

        $assignments = $query->orderBy('created_at', 'desc')->paginate(15);

        // Get filter options
        $users = User::where('company_id', $companyId)->where('active', true)->get();
        $statuses = ['assigned', 'accepted', 'in_progress', 'completed', 'rejected'];
        $assignmentTypes = ['primary', 'secondary', 'supervisor', 'reviewer'];

        return view('job-assignments.index', compact('assignments', 'users', 'statuses', 'assignmentTypes'));
    }

    public function create(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $companyId = Auth::user()->company_id;
        $users = User::where('company_id', $companyId)
                    ->where('active', true)
                    ->with('userRole')
                    ->get();

        $userRoles = UserRole::where('active', true)->get();

        // Get existing assignments for this job
        $existingAssignments = $job->activeAssignments()->with('user')->get();

        return view('job-assignments.create', compact('job', 'users', 'userRoles', 'existingAssignments'));
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
            $assignedUser= $user;

JobActivityLogger::logJobAssigned($job, $assignedUser, $request->assignment_type);
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

        $assignment->load(['job.jobType', 'job.client', 'user.userRole', 'assignedBy']);

        return view('job-assignments.show', compact('assignment'));
    }

    public function updateStatus(Request $request, JobAssignment $assignment)
    {
        if ($assignment->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Only the assigned user can update their assignment status
        if ($assignment->user_id !== Auth::id()) {
            return response()->json(['error' => 'You can only update your own assignments'], 403);
        }

        $request->validate([
            'status' => 'required|in:accepted,rejected,in_progress,completed',
            'notes' => 'nullable|string|max:1000'
        ]);

        $status = $request->status;

        // Validate status transitions
        switch ($status) {
            case 'accepted':
                if (!$assignment->canBeAccepted()) {
                    return response()->json(['error' => 'Cannot accept this assignment in its current state'], 400);
                }
                break;
            case 'rejected':
                if (!$assignment->canBeRejected()) {
                    return response()->json(['error' => 'Cannot reject this assignment in its current state'], 400);
                }
                break;
            case 'in_progress':
                if (!$assignment->canBeStarted()) {
                    return response()->json(['error' => 'Cannot start this assignment in its current state'], 400);
                }
                break;
            case 'completed':
                if (!$assignment->canBeCompleted()) {
                    return response()->json(['error' => 'Cannot complete this assignment in its current state'], 400);
                }
                break;
        }

        try {
            DB::beginTransaction();

            // Update assignment using model methods
            switch ($status) {
                case 'accepted':
                    $assignment->accept($request->notes);
                    break;
                case 'rejected':
                    $assignment->reject($request->notes);
                    break;
                case 'in_progress':
                    $assignment->start($request->notes);
                    break;
                case 'completed':
                    $assignment->complete($request->notes);
                    break;
            }

            // Log the status change
            \App\Models\Log::create([
                'action' => 'job_assignment_status_updated',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Updated assignment status for job {$assignment->job->id} to {$status}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Assignment status updated successfully',
                'new_status' => $status,
                'job_status' => $assignment->job->fresh()->status
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['error' => 'Failed to update assignment status'], 500);
        }
    }

    public function destroy(JobAssignment $assignment)
    {
        if ($assignment->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Only allow removal if assignment hasn't been accepted
        if (!in_array($assignment->status, ['assigned', 'rejected'])) {
            return back()->withErrors(['error' => 'Cannot remove assignment that has been accepted or is in progress']);
        }

        $assignment->update([
            'active' => false,
            'updated_by' => Auth::id()
        ]);

        // Log the removal
        \App\Models\Log::create([
            'action' => 'job_assignment_removed',
            'user_id' => Auth::id(),
            'user_role_id' => Auth::user()->user_role_id,
            'ip_address' => request()->ip(),
            'description' => "Removed assignment for job {$assignment->job->id} from {$assignment->user->name}",
            'active' => true
        ]);

        return back()->with('success', 'Assignment removed successfully');
    }

    public function myAssignments(Request $request)
    {
        $userId = Auth::id();

        $query = JobAssignment::with(['job.jobType', 'job.client', 'assignedBy'])
                             ->where('user_id', $userId)
                             ->where('active', true);

        // Apply filters
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }

        if ($request->filled('assignment_type')) {
            $query->where('assignment_type', $request->assignment_type);
        }

        $assignments = $query->orderBy('assigned_date', 'desc')->paginate(15);

        // Get filter options
        $statuses = ['assigned', 'accepted', 'in_progress', 'completed', 'rejected'];
        $assignmentTypes = ['primary', 'secondary', 'supervisor', 'reviewer'];

        return view('job-assignments.my-assignments', compact('assignments', 'statuses', 'assignmentTypes'));
    }
}
