<?php

namespace App\Http\Controllers;

use App\Models\Task;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class EmployeeTaskController extends Controller
{
    public function startTask(Request $request, Task $task)
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

        try {
            DB::beginTransaction();

            $taskAssignment->update([
                'status' => 'in_progress',
                'updated_by' => Auth::id(),
            ]);

            // Log task start
            \App\Models\Log::create([
                'action' => 'task_started',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Started task {$task->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Task started successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to start task: ' . $e->getMessage()
            ], 500);
        }
    }

    public function completeTask(Request $request, Task $task)
    {
        $request->validate([
            'completion_notes' => 'nullable|string|max:1000',
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
                'status' => 'completed',
                'notes' => $request->completion_notes,
                'updated_by' => Auth::id(),
            ]);

            // Log task completion
            \App\Models\Log::create([
                'action' => 'task_completed',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Completed task {$task->id}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Task completed successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to complete task: ' . $e->getMessage()
            ], 500);
        }
    }
}
