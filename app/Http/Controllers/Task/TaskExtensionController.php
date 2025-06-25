<?php

namespace App\Http\Controllers\Task;

use Carbon\Carbon;
use App\Models\Job;
use App\Models\Task;
use App\Models\Employee;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

use App\Services\JobActivityLogger;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use App\Models\TaskExtensionRequest;
use Illuminate\Support\Facades\Auth;

class TaskExtensionController extends Controller
{
    /**
     * Display extension requests for approval (Supervisors/TOs)
     */
    public function index(Request $request)
    {
        $companyId = Auth::user()->company_id;
        $userRole = Auth::user()->userRole->name ?? '';

        // Check if user can approve extensions
        if (!in_array($userRole, ['Supervisor', 'Technical Officer', 'Engineer'])) {
            abort(403, 'You do not have permission to approve task extensions.');
        }

        $query = TaskExtensionRequest::with([
            'job',
            'task',
            'employee.user',
            'requestedBy'
        ])->forCompany($companyId);

        // Filter by status
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        } else {
            $query->pending(); // Default to pending requests
        }

        // Additional filtering for supervisors (only their created jobs)
        if ($userRole === 'Supervisor') {
            $query->forSupervisor(Auth::id());
        }

        $extensionRequests = $query->orderBy('created_at', 'desc')->paginate(15);

        return view('tasks.extension.index', compact('extensionRequests'));
    }

    /**
     * Show form for requesting task extension (Employees)
     */
    public function create(Task $task)
    {
        $employee = Employee::where('user_id', Auth::id())->first();

        if (!$employee) {
            abort(403, 'Employee record not found.');
        }

        // Get the job of this task
        $job = Job::findOrFail($task->job_id);

        // Check if employee is assigned to this task
        $jobEmployee = JobEmployee::where('task_id', $task->id)
            ->where('employee_id', $employee->id)
            ->first();

        if (!$jobEmployee) {
            abort(403, 'You are not assigned to this task.');
        }

        // Check if task is not completed
        if ($task->status === 'completed') {
            return redirect()->back()->with('error', 'Cannot request extension for completed task.');
        }

        // Check if there's already a pending request for this task
        $existingRequest = TaskExtensionRequest::where('task_id', $task->id)
            ->where('employee_id', $employee->id)
            ->where('status', 'pending')
            ->first();

        if ($existingRequest) {
            return redirect()->back()->with('error', 'You already have a pending extension request for this task.');
        }

        // $job= $task->job;

        return view('tasks.extension.create', compact('task', 'jobEmployee', 'employee','job'));
    }

    /**
     * Store task extension request
     */
    public function requestTaskExtension(Request $request, Task $task)
    {
       $request->validate([
          'requested_end_date' => 'required|date|after:today',
          'reason' => 'required|string|max:1000',
          'justification' => 'nullable|string|max:1000',
       ]);

       try {
          DB::beginTransaction();

          $job = Job::findOrFail($task->job_id);
          $employee = Employee::where('user_id', Auth::id())->first();

          if (!$employee) {
             throw new \Exception('Employee record not found.');
          }

          // Get current end date
          $jobEmployee = JobEmployee::where('task_id', $task->id)
             ->where('employee_id', $employee->id)
             ->first();

          if (!$jobEmployee) {
             throw new \Exception('Task assignment not found.');
          }

          $currentEndDate = $jobEmployee->end_date;
          $requestedEndDate = $request->requested_end_date;
          $extensionDays = Carbon::parse((string)$requestedEndDate)->diffInDays(Carbon::parse((string)$currentEndDate));

          // Create extension request
          TaskExtensionRequest::create([
             'job_id' => $job->id,
             'task_id' => $task->id,
             'employee_id' => $employee->id,
             'requested_by' => Auth::id(),
             'current_end_date' => $currentEndDate,
             'requested_end_date' => $requestedEndDate,
             'extension_days' => $extensionDays,
             'reason' => $request->reason,
             'justification' => $request->justification,
             'status' => 'pending',
             'created_by' => Auth::id(),
             'updated_by' => Auth::id(),
          ]);

  
          // Log extension request
          JobActivityLogger::logTaskExtensionRequested(
             $job,
             $task,
             $employee,
             $currentEndDate,
             $requestedEndDate,
             $request->reason
          );
          DB::commit();

          return redirect()->back()
             ->with('success', 'Extension request submitted successfully!');

       } catch (\Exception $e) {
          DB::rollBack();
          Log::error('Task extension request failed: ' . $e->getMessage(), ['exception' => $e]);
          return redirect()->back()
             ->with('error', 'Failed to submit extension request. Please try again. Error: ' . $e->getMessage())
             ->withInput();
       }
    }

    /**
     * Show specific extension request
     */
    public function show(TaskExtensionRequest $extensionRequest)
    {
        $companyId = Auth::user()->company_id;

        // Check if request belongs to user's company
        if ($extensionRequest->job->company_id !== $companyId) {
            abort(403);
        }

        $userRole = Auth::user()->userRole->name ?? '';

        // Check permissions
        if (!in_array($userRole, ['Supervisor', 'Technical Officer', 'Engineer'])) {
            abort(403, 'You do not have permission to view this request.');
        }

        // Additional check for supervisors
        if ($userRole === 'Supervisor' && $extensionRequest->job->created_by !== Auth::id()) {
            abort(403, 'You can only view extension requests for jobs you created.');
        }

        $extensionRequest->load([
            'job',
            'task',
            'employee.user',
            'requestedBy',
            'reviewedBy'
        ]);

        return view('tasks.extension.show', compact('extensionRequest'));
    }

    /**
     * Approve extension request
     */
    public function approve(Request $request, TaskExtensionRequest $extensionRequest)
    {

        return $this->processRequest($request, $extensionRequest, 'approved');

    }

    /**
     * Reject extension request
     */
    public function reject(Request $request, TaskExtensionRequest $extensionRequest)
    {
        return $this->processRequest($request, $extensionRequest, 'rejected');
    }

    /**
     * Process extension request (approve/reject)
     */
   public function processTaskExtension(Request $request, TaskExtensionRequest $extensionRequest)
    {
        $request->validate([
            'action' => 'required|in:approve,reject',
            'review_notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $job = $extensionRequest->job;
            $task = $extensionRequest->task;
            $employee = $extensionRequest->employee;
            $action = $request->action;

            // Update extension request
            $extensionRequest->update([
                'status' => $action === 'approve' ? 'approved' : 'rejected',
                'reviewed_by' => Auth::id(),
                'reviewed_at' => now(),
                'review_notes' => $request->review_notes,
                'updated_by' => Auth::id(),
            ]);

            if ($action === 'approve') {
                // Update task deadline
                JobEmployee::where('task_id', $task->id)
                    ->where('employee_id', $employee->id)
                    ->update([
                        'end_date' => $extensionRequest->requested_end_date,
                        'duration_in_days' => \Carbon\Carbon::parse($extensionRequest->requested_end_date)
                            ->diffInDays(\Carbon\Carbon::parse($extensionRequest->current_end_date)) + 1,
                        'updated_by' => Auth::id(),
                    ]);

                // Update job due date if necessary
                if (!$job->due_date || $extensionRequest->requested_end_date > $job->due_date) {
                    $job->update([
                        'due_date' => $extensionRequest->requested_end_date,
                        'updated_by' => Auth::id(),
                    ]);
                }
            }

            // Log extension processing
            JobActivityLogger::logTaskExtensionProcessed(
                $job,
                $task,
                $employee,
                $action === 'approve' ? 'approved' : 'rejected',
                $request->review_notes
            );

            DB::commit();

            $message = $action === 'approve'
                ? 'Task extension approved successfully!'
                : 'Task extension rejected.';

            return redirect()->route('tasks.extension.index')
                ->with('success', $message);

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()
                ->with('error', 'Failed to process extension request. Please try again.');
        }
    }

    /**
     * Show employee's own extension requests
     */
    public function myRequests(Request $request)
    {
        $employee = Employee::where('user_id', Auth::id())->first();

        if (!$employee) {
            abort(403, 'Employee record not found.');
        }

        $query = TaskExtensionRequest::with([
            'job',
            'task',
            'reviewedBy'
        ])->where('employee_id', $employee->id);

        // Filter by status
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }

        $extensionRequests = $query->orderBy('created_at', 'desc')->paginate(15);

        return view('tasks.extension.my-requests', compact('extensionRequests'));
    }

    /**
     * Get pending extension requests count for dashboard
     */
    public function getPendingCount()
    {
        $companyId = Auth::user()->company_id;
        $userRole = Auth::user()->userRole->name ?? '';

        $query = TaskExtensionRequest::forCompany($companyId)->pending();

        // Filter by role
        if ($userRole === 'Supervisor') {
            $query->forSupervisor(Auth::id());
        }

        return response()->json([
            'pending_count' => $query->count()
        ]);
    }

    /**
     * Calculate duration in days
     */
    private function calculateDuration($startDate, $endDate)
    {
        if (!$startDate || !$endDate) {
            return null;
        }

        return Carbon::parse($startDate)->diffInDays(Carbon::parse($endDate)) + 1;
    }
}
