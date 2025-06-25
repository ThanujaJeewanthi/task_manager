<?php

namespace App\Http\Controllers;

use App\Models\Job;
use App\Models\Task;
use App\Models\Employee;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Services\JobActivityLogger;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Job\JobController;

class EmployeeTaskController extends Controller
{
    /**
     * Start a task
     */
    public function startTask(Request $request, Task $task)
    {
        $user = Auth::user();
        $employee = Employee::where('user_id', $user->id)->first();

        if (!$employee) {
            return response()->json(['error' => 'Employee record not found'], 403);
        }

        // Check if employee is assigned to this task
        $jobEmployee = JobEmployee::where('employee_id', $employee->id)
            ->where('task_id', $task->id)
            ->first();

        if (!$jobEmployee) {
            return response()->json(['error' => 'You are not assigned to this task'], 403);
        }

        if ($task->status !== 'pending') {
            return response()->json(['error' => 'Task cannot be started'], 400);
        }

        try {
            DB::beginTransaction();

            // Update task status
            $task->update([
                'status' => 'in_progress',
                'updated_by' => Auth::id(),
            ]);

// Update job employee status
$jobEmployee->update([
    'status' => 'in_progress',
    'start_date' => now()->toDateString(),
]);

// Get the job instance
$job = $task->job;

// Auto-update job status
$jobController = new JobController();
$jobController->updateJobStatusBasedOnTasks($job);

DB::commit();
// After task status update, add:
JobActivityLogger::logTaskStarted($job, $task, $employee);
return redirect()->back()
    ->with('success', 'Task started successfully');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()
            ->with('error', 'Failed to start task');
        }
    }

    public function completeTask(Request $request, Task $task)
    {
        $request->validate([
            'completion_notes' => 'nullable|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $job = $task->job;
            $employee = Employee::where('user_id', Auth::id())->first();

            if (!$employee) {
                throw new \Exception('Employee record not found.');
            }

            // Update task status in job_employees
            JobEmployee::where('task_id', $task->id)
                ->where('employee_id', $employee->id)
                ->update([
                    'status' => 'completed',
                    'notes' => $request->completion_notes,
                ]);

            // Update task status if all employees completed
            $pendingCount = JobEmployee::where('task_id', $task->id)
                ->where('status', '!=', 'completed')
                ->count();

            if ($pendingCount === 0) {
                $task->update(['status' => 'completed']);
            }

            // Log task completion
            JobActivityLogger::logTaskCompleted($job, $task, $employee, $request->completion_notes);

            // Check if all tasks are completed to update job status
            $pendingTasks = Task::where('job_id', $job->id)
                ->where('status', '!=', 'completed')
                ->count();

            if ($pendingTasks === 0) {
                $oldStatus = $job->status;
                $job->update(['status' => 'completed', 'completed_date' => now()]);

                // Log job completion
                JobActivityLogger::logJobStatusChanged($job, $oldStatus, 'completed', 'All tasks completed');
                JobActivityLogger::logJobCompleted($job, 'All tasks have been completed successfully');
            }

            DB::commit();

            return redirect()->back()
                ->with('success', 'Task completed successfully!');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()
                ->with('error', 'Failed to complete task. Please try again.');
        }
    }
}
