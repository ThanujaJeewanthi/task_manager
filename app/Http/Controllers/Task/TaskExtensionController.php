<?php

namespace App\Http\Controllers;

use App\Models\Task;
use App\Models\TaskExtensionRequest;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class TaskExtensionController extends Controller
{
    public function create(Task $task)
    {
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

        return view('tasks.extension-request', compact('task', 'taskAssignment'));
    }

    public function requestTaskExtension(Request $request, Task $task)
    {
        $request->validate([
            'extension_days' => 'required|integer|min:1|max:365',
            'reason' => 'required|string|max:1000',
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

        // Check if there's already a pending request
        $existingRequest = TaskExtensionRequest::where('task_id', $task->id)
            ->where('requested_by', Auth::id())
            ->where('status', 'pending')
            ->first();

        if ($existingRequest) {
            return redirect()->back()->with('error', 'You already have a pending extension request for this task.');
        }

        try {
            DB::beginTransaction();

            TaskExtensionRequest::create([
                'task_id' => $task->id,
                'job_id' => $task->job_id,
                'requested_by' => Auth::id(),
                'extension_days' => $request->extension_days,
                'reason' => $request->reason,
                'current_end_date' => $taskAssignment->end_date,
                'requested_end_date' => $taskAssignment->end_date ? 
                    Carbon::parse($taskAssignment->end_date)->addDays($request->extension_days) : null,
                'status' => 'pending',
                'created_by' => Auth::id(),
            ]);

            // Log the request
            \App\Models\Log::create([
                'action' => 'task_extension_requested',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Requested {$request->extension_days} day extension for task {$task->id}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->back()->with('success', 'Extension request submitted successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to submit extension request.')->withInput();
        }
    }

    public function index()
    {
        $companyId = Auth::user()->company_id;

        $extensionRequests = TaskExtensionRequest::with(['task', 'job.jobType', 'requestedBy'])
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })
            ->where('status', 'pending')
            ->orderBy('created_at', 'desc')
            ->paginate(15);

        return view('tasks.extension-requests', compact('extensionRequests'));
    }

    public function show(TaskExtensionRequest $extensionRequest)
    {
        if ($extensionRequest->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $extensionRequest->load(['task', 'job.jobType', 'requestedBy']);
        return view('tasks.extension-request-details', compact('extensionRequest'));
    }

    public function approve(Request $request, TaskExtensionRequest $extensionRequest)
    {
        if ($extensionRequest->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'approved_days' => 'required|integer|min:1|max:365',
            'approval_notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            // Update the extension request
            $extensionRequest->update([
                'status' => 'approved',
                'approved_by' => Auth::id(),
                'approved_at' => now(),
            // Update the extension request
            $extensionRequest->update([
                'status' => 'approved',
                'approved_by' => Auth::id(),
                'approved_at' => now(),
                'approved_days' => $request->approved_days,
                'approval_notes' => $request->approval_notes,
                'updated_by' => Auth::id(),
            ]);

            // Update the task assignment
            $taskAssignment = JobEmployee::where('task_id', $extensionRequest->task_id)
                ->where('user_id', $extensionRequest->requested_by)
                ->first();

            if ($taskAssignment && $taskAssignment->end_date) {
                $newEndDate = Carbon::parse($taskAssignment->end_date)->addDays($request->approved_days);
                $taskAssignment->update([
                    'end_date' => $newEndDate,
                    'duration_in_days' => $taskAssignment->start_date ? 
                        Carbon::parse($taskAssignment->start_date)->diffInDays($newEndDate) + 1 : null,
                    'updated_by' => Auth::id(),
                ]);
            }

            // Log the approval
            \App\Models\Log::create([
                'action' => 'task_extension_approved',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Approved {$request->approved_days} day extension for task {$extensionRequest->task_id}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->back()->with('success', 'Extension request approved successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to approve extension request.');
        }
    }

    public function reject(Request $request, TaskExtensionRequest $extensionRequest)
    {
        if ($extensionRequest->job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'rejection_reason' => 'required|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $extensionRequest->update([
                'status' => 'rejected',
                'rejected_by' => Auth::id(),
                'rejected_at' => now(),
                'rejection_reason' => $request->rejection_reason,
                'updated_by' => Auth::id(),
            ]);

            // Log the rejection
            \App\Models\Log::create([
                'action' => 'task_extension_rejected',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Rejected extension request for task {$extensionRequest->task_id}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->back()->with('success', 'Extension request rejected.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to reject extension request.');
        }
    }

    public function myRequests()
    {
        $companyId = Auth::user()->company_id;

        $myRequests = TaskExtensionRequest::with(['task', 'job.jobType', 'approvedBy', 'rejectedBy'])
            ->whereHas('job', function ($query) use ($companyId) {
                $query->where('company_id', $companyId);
            })
            ->where('requested_by', Auth::id())
            ->orderBy('created_at', 'desc')
            ->paginate(15);

        return view('tasks.my-extension-requests', compact('myRequests'));
    }

    public function getPendingCount()
    {
        $companyId = Auth::user()->company_id;

        $count = TaskExtensionRequest::whereHas('job', function ($query) use ($companyId) {
            $query->where('company_id', $companyId);
        })->where('status', 'pending')->count();

        return response()->json(['count' => $count]);
    }
}