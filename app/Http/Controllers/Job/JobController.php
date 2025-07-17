<?php

namespace App\Http\Controllers\Job;

use Carbon\Carbon;
use App\Models\Job;
use App\Models\Item;
use App\Models\Task;
use App\Models\User;
use App\Models\Client;
use App\Models\JobType;
use App\Models\Equipment;
use App\Models\JobOption;
use App\Models\JobEmployee;
use Illuminate\Http\Request;
use App\Models\JobActivityLog;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\DB;
use App\Services\JobActivityLogger;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;
use App\Models\JobItems;

class JobController extends Controller
{
    public function index(Request $request)
    {
        $companyId = Auth::user()->company_id;

        // Initialize query - remove role-based filtering, let middleware handle permissions
        $query = Job::with(['jobType', 'client', 'equipment', 'jobEmployees.user'])
            ->where('company_id', $companyId)
            ->where('active', true);

        // Handle sorting
        $sortBy = $request->input('sort_by', 'priority');
        $sortOrder = $request->input('sort_order', 'asc');

        $allowedSorts = ['id', 'priority', 'start_date', 'due_date'];
        if (!in_array($sortBy, $allowedSorts)) {
            $sortBy = 'priority';
        }

        if ($sortBy === 'priority') {
            $query->orderBy('priority', $sortOrder)
                  ->orderBy('start_date', 'asc');
        } else {
            $query->orderBy($sortBy, $sortOrder);
        }

        // Handle filters
        if ($request->filled('job_type_id')) {
            $query->where('job_type_id', $request->input('job_type_id'));
        }

        if ($request->filled('client_id')) {
            $query->where('client_id', $request->input('client_id'));
        }

        if ($request->filled('equipment_id')) {
            $query->where('equipment_id', $request->input('equipment_id'));
        }

        if ($request->filled('id')) {
            $query->where('id', 'like', '%' . $request->input('id') . '%');
        }

        if ($request->filled('status')) {
            $query->where('status', $request->input('status'));
        }

        if ($request->filled('priority')) {
            $query->where('priority', $request->input('priority'));
        }

        $jobs = $query->paginate(15)->withQueryString();

        $jobTypes = JobType::where('company_id', $companyId)->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        return view('jobs.index', compact('jobs', 'jobTypes', 'clients', 'equipments'));
    }

    public function create()
    {
        $companyId = Auth::user()->company_id;
        
        $jobTypes = JobType::where('company_id', $companyId)->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        return view('jobs.create', compact('jobTypes', 'clients', 'equipments'));
    }

    public function store(Request $request)
    {
        $request->validate([
            'job_type_id' => 'required|exists:job_types,id',
            'client_id' => 'nullable|exists:clients,id',
            'equipment_id' => 'nullable|exists:equipments,id',
            'description' => 'nullable|string',
            'priority' => 'required|in:1,2,3,4',
            'start_date' => 'nullable|date',
            'due_date' => 'nullable|date|after_or_equal:start_date',
            'photos' => 'nullable|array',
            'photos.*' => 'image|mimes:jpeg,png,jpg,gif|max:2048',
        ]);

        try {
            DB::beginTransaction();

            $photos = [];
            if ($request->hasFile('photos')) {
                foreach ($request->file('photos') as $photo) {
                    $path = $photo->store('job-photos', 'public');
                    $photos[] = $path;
                }
            }

            $job->update([
                'job_type_id' => $request->job_type_id,
                'client_id' => $request->client_id,
                'equipment_id' => $request->equipment_id,
                'description' => $request->description,
                'priority' => $request->priority,
                'start_date' => $request->start_date,
                'due_date' => $request->due_date,
                'photos' => $photos,
                'updated_by' => Auth::id(),
            ]);

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Job updated successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Job update failed.')->withInput();
        }
    }

    public function destroy(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $job->update(['active' => false, 'updated_by' => Auth::id()]);
        return redirect()->route('jobs.index')->with('success', 'Job deleted successfully.');
    }

    public function createTask(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Get all active users from the same company instead of employees
        $users = User::where('company_id', Auth::user()->company_id)
                    ->where('active', true)
                    ->with('userRole')
                    ->get();

        return view('tasks.create', compact('job', 'users'));
    }

    public function storeTask(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) { 
            abort(403);
        }

        $request->validate([
            'task' => 'required|string|max:255',
            'description' => 'nullable|string',
            'start_date' => 'nullable|date',
            'end_date' => 'nullable|date|after_or_equal:start_date',
            'user_ids' => 'required|array',
            'user_ids.*' => 'exists:users,id',
            'notes' => 'nullable|string',
        ]);

        // Validate that all selected users belong to the same company
        $validUsers = User::whereIn('id', $request->user_ids)
                         ->where('company_id', Auth::user()->company_id)
                         ->where('active', true)
                         ->pluck('id');

        if ($validUsers->count() !== count($request->user_ids)) {
            return redirect()->back()->withErrors(['user_ids' => 'Some selected users are invalid.']);
        }

        try {
            DB::beginTransaction();

            $task = Task::create([
                'task' => $request->task,
                'description' => $request->description,
                'job_id' => $job->id,
                'status' => 'pending',
                'active' => $request->has('is_active'),
                'created_by' => Auth::id(),
            ]);

            foreach ($request->user_ids as $userId) {
                $job->jobEmployees()->create([
                    'user_id' => $userId,
                    'task_id' => $task->id,
                    'start_date' => $request->start_date,
                    'end_date' => $request->end_date,
                    'duration_in_days' => $request->start_date && $request->end_date ?
                     Carbon::parse($request->start_date)->diffInDays(Carbon::parse($request->end_date)) + 1 : null,
                    'status' => 'pending',
                    'notes' => $request->notes,
                    'created_by' => Auth::id(),
                    'updated_by' => Auth::id(),
                ]);
            }

            // Log task creation
            $assignedUsers = User::whereIn('id', $request->user_ids)->get();
            JobActivityLogger::logTaskCreated($job, $task, $assignedUsers);

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Task created and users assigned successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Task creation failed.')->withInput();
        }
    }

    public function editTask(Job $job, Task $task)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Get all active users from the same company
        $users = User::where('company_id', Auth::user()->company_id)
                    ->where('active', true)
                    ->with('userRole')
                    ->get();

        return view('tasks.edit', compact('job', 'task', 'users'));
    }

    public function updateTask(Request $request, Job $job, Task $task)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'task' => 'required|string|max:255',
            'description' => 'nullable|string',
            'start_date' => 'nullable|date',
            'end_date' => 'nullable|date|after_or_equal:start_date',
            'user_ids' => 'required|array',
            'user_ids.*' => 'exists:users,id',
            'notes' => 'nullable|string',
        ]);

        // Validate that all selected users belong to the same company
        $validUsers = User::whereIn('id', $request->user_ids)
                         ->where('company_id', Auth::user()->company_id)
                         ->where('active', true)
                         ->pluck('id');

        if ($validUsers->count() !== count($request->user_ids)) {
            return redirect()->back()->withErrors(['user_ids' => 'Some selected users are invalid.']);
        }

        try {
            DB::beginTransaction();

            $task->update([
                'task' => $request->task,
                'job_id' => $job->id,
                'description' => $request->description,
                'status' => 'pending',
                'active' => $request->has('is_active'),
                'updated_by' => Auth::id(),
            ]);

            // Delete existing job_employee records for this task
            $job->jobEmployees()->where('task_id', $task->id)->delete();

            // Create new job_employee records
            foreach ($request->user_ids as $userId) {
                $job->jobEmployees()->create([
                    'user_id' => $userId,
                    'task_id' => $task->id,
                    'start_date' => $request->start_date,
                    'end_date' => $request->end_date,
                    'duration_in_days' => $request->start_date && $request->end_date ?
                        Carbon::parse($request->start_date)->diffInDays(Carbon::parse($request->end_date)) + 1 : null,
                    'status' => 'pending',
                    'notes' => $request->notes,
                    'created_by' => Auth::id(),
                    'updated_by' => Auth::id(),
                ]);
            }

            // Log task update
            $assignedUsers = User::whereIn('id', $request->user_ids)->get();
            JobActivityLogger::logTaskUpdated($job, $task, $assignedUsers);

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Task updated successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Task update failed.')->withInput();
        }
    }

    public function destroyTask(Job $job, Task $task)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        try {
            DB::beginTransaction();

            // Delete related job_employee records
            $job->jobEmployees()->where('task_id', $task->id)->delete();
            
            // Delete the task
            $task->delete();

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Task deleted successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Task deletion failed.');
        }
    }

    public function addItems(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $items = Item::where('company_id', Auth::user()->company_id)->where('active', true)->get();
        return view('jobs.add-items', compact('job', 'items'));
    }

    public function storeItems(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'items' => 'required|array',
            'items.*.item_id' => 'required|exists:items,id',
            'items.*.quantity' => 'required|numeric|min:1',
            'items.*.notes' => 'nullable|string',
        ]);

        try {
            DB::beginTransaction();

            foreach ($request->items as $itemData) {
                JobItems::updateOrCreate(
                    [
                        'job_id' => $job->id,
                        'item_id' => $itemData['item_id'],
                    ],
                    [
                        'quantity' => $itemData['quantity'],
                        'notes' => $itemData['notes'] ?? null,
                        'created_by' => Auth::id(),
                        'updated_by' => Auth::id(),
                    ]
                );
            }

            // Update job to request approval
            $job->update([
                'approval_status' => 'requested',
                'updated_by' => Auth::id(),
            ]);

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Items added and approval requested.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to add items.')->withInput();
        }
    }

    public function showApproval(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        if ($job->approval_status !== 'requested') {
            return redirect()->route('jobs.show', $job)->with('error', 'Job is not awaiting approval.');
        }

        $job->load('jobItems.item');
        return view('jobs.approval', compact('job'));
    }

    public function processApproval(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'action' => 'required|in:approve,reject',
            'notes' => 'nullable|string',
            'items' => 'array',
            'items.*.id' => 'exists:job_items,id',
            'items.*.quantity' => 'numeric|min:1',
        ]);

        try {
            DB::beginTransaction();

            if ($request->action === 'approve') {
                // Update item quantities if provided
                if ($request->has('items')) {
                    foreach ($request->items as $itemData) {
                        JobItems::where('id', $itemData['id'])->update([
                            'quantity' => $itemData['quantity'],
                            'updated_by' => Auth::id(),
                        ]);
                    }
                }

                $job->update([
                    'approval_status' => 'approved',
                    'approved_by' => Auth::id(),
                    'approved_at' => now(),
                    'approval_notes' => $request->notes,
                    'updated_by' => Auth::id(),
                ]);

                $message = 'Job approved successfully.';
            } else {
                $job->update([
                    'approval_status' => 'rejected',
                    'rejected_by' => Auth::id(),
                    'rejected_at' => now(),
                    'rejection_notes' => $request->notes,
                    'updated_by' => Auth::id(),
                ]);

                $message = 'Job rejected successfully.';
            }

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', $message);

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to process approval.')->withInput();
        }
    }

    public function getJobTypeOptions($jobTypeId)
    {
        $jobType = JobType::with('jobOptions')->findOrFail($jobTypeId);
        return response()->json(['options' => $jobType->jobOptions]);
    }

    public function copy(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $companyId = Auth::user()->company_id;
        $jobTypes = JobType::where('company_id', $companyId)->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        return view('jobs.copy', compact('job', 'jobTypes', 'clients', 'equipments'));
    }

    public function storeCopy(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'job_type_id' => 'required|exists:job_types,id',
            'client_id' => 'nullable|exists:clients,id',
            'equipment_id' => 'nullable|exists:equipments,id',
            'description' => 'nullable|string',
            'priority' => 'required|in:1,2,3,4',
            'start_date' => 'nullable|date',
            'due_date' => 'nullable|date|after_or_equal:start_date',
        ]);

        try {
            DB::beginTransaction();

            $newJob = $job->replicate();
            $newJob->job_type_id = $request->job_type_id;
            $newJob->client_id = $request->client_id;
            $newJob->equipment_id = $request->equipment_id;
            $newJob->description = $request->description;
            $newJob->priority = $request->priority;
            $newJob->start_date = $request->start_date;
            $newJob->due_date = $request->due_date;
            $newJob->status = 'pending';
            $newJob->created_by = Auth::id();
            $newJob->updated_by = Auth::id();
            $newJob->save();

            DB::commit();

            return redirect()->route('jobs.show', $newJob)->with('success', 'Job copied successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Job copy failed.')->withInput();
        }
    }

    private function getTimelineData(Job $job)
    {
        $timeline = [];

        // Add job creation
        $timeline[] = [
            'type' => 'job_created',
            'date' => $job->created_at,
            'user' => $job->creator->name ?? 'System',
            'description' => 'Job created'
        ];

        // Add task assignments
        foreach ($job->tasks as $task) {
            $timeline[] = [
                'type' => 'task_created',
                'date' => $task->created_at,
                'user' => $task->creator->name ?? 'System',
                'description' => "Task '{$task->task}' created"
            ];

            foreach ($task->jobEmployees as $assignment) {
                $timeline[] = [
                    'type' => 'user_assigned',
                    'date' => $assignment->created_at,
                    'user' => $assignment->creator->name ?? 'System',
                    'description' => "User '{$assignment->user->name}' assigned to task '{$task->task}'"
                ];
            }
        }

        // Sort by date
        usort($timeline, function($a, $b) {
            return $a['date'] <=> $b['date'];
        });

        return $timeline;
    }

    private function getJobStats(Job $job)
    {
        $tasks = $job->tasks;
        $totalTasks = $tasks->count();

        if ($totalTasks === 0) {
            return [
                'total_tasks' => 0,
                'completed_tasks' => 0,
                'in_progress_tasks' => 0,
                'pending_tasks' => 0,
                'cancelled_tasks' => 0,
                'overall_progress' => 0,
                'user_assignments' => 0,
                'completed_assignments' => 0
            ];
        }

        $completedTasks = $tasks->where('status', 'completed')->count();
        $inProgressTasks = $tasks->where('status', 'in_progress')->count();
        $pendingTasks = $tasks->where('status', 'pending')->count();
        $cancelledTasks = $tasks->where('status', 'cancelled')->count();

        $overallProgress = round(($completedTasks / $totalTasks) * 100);

        $totalAssignments = JobEmployee::whereIn('task_id', $tasks->pluck('id'))->count();
        $completedAssignments = JobEmployee::whereIn('task_id', $tasks->pluck('id'))
            ->where('status', 'completed')->count();

        return [
            'total_tasks' => $totalTasks,
            'completed_tasks' => $completedTasks,
            'in_progress_tasks' => $inProgressTasks,
            'pending_tasks' => $pendingTasks,
            'cancelled_tasks' => $cancelledTasks,
            'overall_progress' => $overallProgress,
            'user_assignments' => $totalAssignments,
            'completed_assignments' => $completedAssignments,
            'assignment_completion_rate' => $totalAssignments > 0 ? round(($completedAssignments / $totalAssignments) * 100) : 0
        ];
    }

    public function getTimelineJson(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        return response()->json([
            'timeline' => $this->getTimelineData($job),
            'stats' => $this->getJobStats($job)
        ]);
    }

    public function getTaskDetails(Job $job, Task $task)
    {
        Log::info('getTaskDetails called', ['job_id' => $job->id, 'task_id' => $task->id]);
        
        if ($job->company_id !== Auth::user()->company_id || $task->job_id !== $job->id) {
            abort(403);
        }

        $task->load([
            'jobEmployees' => function($query) {
                $query->with('user.userRole');
            },
            'taskExtensionRequests' => function($query) {
                $query->where('status', 'pending');
            }
        ]);

        $taskUsers = $task->jobEmployees;
        $progress = $this->calculateTaskProgress($task, $taskUsers);

        return response()->json([
            'task' => [
                'id' => $task->id,
                'name' => $task->task,
                'description' => $task->description ?? 'No description',
                'status' => $task->status,
                'progress' => $progress
            ],
            'assigned_users' => $taskUsers->map(function($assignment) {
                return [
                    'id' => $assignment->user->id,
                    'name' => $assignment->user->name,
                    'role' => $assignment->user->userRole->name ?? 'No Role',
                    'status' => $assignment->status,
                    'start_date' => $assignment->start_date,
                    'end_date' => $assignment->end_date,
                    'notes' => $assignment->notes
                ];
            })
        ]);
    }

    private function calculateTaskProgress($task, $taskUsers)
    {
        if ($taskUsers->isEmpty()) {
            return 0;
        }

        $totalUsers = $taskUsers->count();
        $completedUsers = $taskUsers->where('status', 'completed')->count();

        return round(($completedUsers / $totalUsers) * 100);
    }

    public function extendTask(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $tasks = $job->tasks()->with('jobEmployees.user')->get();
        return view('jobs.extend-task', compact('job', 'tasks'));
    }

    public function storeExtendTask(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'task_id' => 'required|exists:tasks,id',
            'extension_days' => 'required|integer|min:1|max:365',
            'reason' => 'required|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $task = Task::findOrFail($request->task_id);
            
            // Update task end date
            if ($task->end_date) {
                $newEndDate = Carbon::parse($task->end_date)->addDays($request->extension_days);
                $task->update(['end_date' => $newEndDate]);
            }

            // Update job employees for this task
            $job->jobEmployees()->where('task_id', $task->id)->each(function ($assignment) use ($request) {
                if ($assignment->end_date) {
                    $newEndDate = Carbon::parse($assignment->end_date)->addDays($request->extension_days);
                    $assignment->update([
                        'end_date' => $newEndDate,
                        'duration_in_days' => $assignment->start_date ? 
                            Carbon::parse($assignment->start_date)->diffInDays($newEndDate) + 1 : null,
                    ]);
                }
            });

            // Log the extension
            \App\Models\Log::create([
                'action' => 'task_extended',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Extended task {$task->id} by {$request->extension_days} days. Reason: {$request->reason}",
                'active' => true
            ]);

            DB::commit();

            return redirect()->route('jobs.show', $job)->with('success', 'Task extended successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to extend task.')->withInput();
        }
    }

    public function showReview(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $job->load([
            'jobType', 'client', 'equipment', 'creator', 'assignedUser',
            'tasks.jobEmployees.user', 'jobItems.item'
        ]);

        return view('jobs.review', compact('job'));
    }

    public function processReview(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'action' => 'required|in:approve,reject,request_changes',
            'review_notes' => 'required|string|max:1000',
        ]);

        try {
            DB::beginTransaction();

            $statusMap = [
                'approve' => 'approved',
                'reject' => 'rejected',
                'request_changes' => 'requested',
            ];

            $job->update([
                'approval_status' => $statusMap[$request->action],
                'approval_notes' => $request->review_notes,
                'updated_by' => Auth::id(),
            ]);

            if ($request->action === 'approve') {
                $job->update([
                    'approved_by' => Auth::id(),
                    'approved_at' => now(),
                ]);
            } elseif ($request->action === 'reject') {
                $job->update([
                    'rejected_by' => Auth::id(),
                    'rejected_at' => now(),
                ]);
            }

            // Log the review
            \App\Models\Log::create([
                'action' => 'job_reviewed',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Reviewed job {$job->id} - Action: {$request->action}",
                'active' => true
            ]);

            DB::commit();

            $message = match($request->action) {
                'approve' => 'Job approved successfully.',
                'reject' => 'Job rejected successfully.',
                'request_changes' => 'Changes requested successfully.',
            };

            return redirect()->route('jobs.show', $job)->with('success', $message);

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Failed to process review.')->withInput();
        }
    }

    public function updateJobStatus(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
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

    public function bulkUpdateStatus(Request $request)
    {
        $request->validate([
            'job_ids' => 'required|array',
            'job_ids.*' => 'exists:jobs,id',
            'status' => 'required|in:pending,in_progress,on_hold,completed,cancelled',
        ]);

        $companyId = Auth::user()->company_id;

        try {
            DB::beginTransaction();

            $updateData = [
                'status' => $request->status,
                'updated_by' => Auth::id(),
            ];

            if ($request->status === 'completed') {
                $updateData['completed_date'] = now();
            }

            Job::whereIn('id', $request->job_ids)
               ->where('company_id', $companyId)
               ->update($updateData);

            // Log bulk status update
            \App\Models\Log::create([
                'action' => 'bulk_job_status_update',
                'user_id' => Auth::id(),
                'user_role_id' => Auth::user()->user_role_id,
                'ip_address' => $request->ip(),
                'description' => "Bulk updated " . count($request->job_ids) . " jobs to status: {$request->status}",
                'active' => true
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => count($request->job_ids) . ' jobs updated successfully!'
            ]);

        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'message' => 'Failed to update jobs: ' . $e->getMessage()
            ], 500);
        }
    }

    public function exportJobs(Request $request)
    {
        $companyId = Auth::user()->company_id;
        
        $query = Job::with(['jobType', 'client', 'equipment', 'creator', 'assignedUser'])
            ->where('company_id', $companyId)
            ->where('active', true);

        // Apply filters if provided
        if ($request->filled('status')) {
            $query->where('status', $request->status);
        }

        if ($request->filled('priority')) {
            $query->where('priority', $request->priority);
        }

        if ($request->filled('job_type_id')) {
            $query->where('job_type_id', $request->job_type_id);
        }

        if ($request->filled('date_from')) {
            $query->whereDate('created_at', '>=', $request->date_from);
        }

        if ($request->filled('date_to')) {
            $query->whereDate('created_at', '<=', $request->date_to);
        }

        $jobs = $query->get();

        $filename = 'jobs_export_' . now()->format('Y-m-d_H-i-s') . '.csv';
        
        $headers = [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => 'attachment; filename="' . $filename . '"',
        ];

        $callback = function() use ($jobs) {
            $file = fopen('php://output', 'w');
            
            // CSV Headers
            fputcsv($file, [
                'Job ID', 'Job Type', 'Client', 'Equipment', 'Description', 
                'Status', 'Priority', 'Start Date', 'Due Date', 'Completed Date',
                'Assigned User', 'Created By', 'Created At'
            ]);

            // CSV Data
            foreach ($jobs as $job) {
                fputcsv($file, [
                    $job->id,
                    $job->jobType->name ?? '',
                    $job->client->name ?? '',
                    $job->equipment->name ?? '',
                    $job->description,
                    $job->status,
                    $job->priority,
                    $job->start_date ? $job->start_date->format('Y-m-d') : '',
                    $job->due_date ? $job->due_date->format('Y-m-d') : '',
                    $job->completed_date ? $job->completed_date->format('Y-m-d') : '',
                    $job->assignedUser->name ?? '',
                    $job->creator->name ?? '',
                    $job->created_at->format('Y-m-d H:i:s'),
                ]);
            }

            fclose($file);
        };

        return response()->stream($callback, 200, $headers);
    }
}
                    $photos[] = $path;
                }
            }

            $job = Job::create([
                'company_id' => Auth::user()->company_id,
                'job_type_id' => $request->job_type_id,
                'client_id' => $request->client_id,
                'equipment_id' => $request->equipment_id,
                'description' => $request->description,
                'priority' => $request->priority,
                'start_date' => $request->start_date,
                'due_date' => $request->due_date,
                'photos' => $photos,
                'status' => 'pending',
                'active' => true,
                'created_by' => Auth::id(),
            ]);

            DB::commit();

            return redirect()->route('jobs.index')->with('success', 'Job created successfully.');

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()->with('error', 'Job creation failed.')->withInput();
        }
    }

    public function show(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $job->load([
            'jobType', 'client', 'equipment', 'creator', 'assignedUser',
            'tasks.jobEmployees.user', 'jobItems.item', 'assignments.user.userRole'
        ]);

        $timeline = $this->getTimelineData($job);
        $stats = $this->getJobStats($job);

        return view('jobs.show', compact('job', 'timeline', 'stats'));
    }

    public function edit(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $companyId = Auth::user()->company_id;
        $jobTypes = JobType::where('company_id', $companyId)->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        return view('jobs.edit', compact('job', 'jobTypes', 'clients', 'equipments'));
    }

    public function update(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([
            'job_type_id' => 'required|exists:job_types,id',
            'client_id' => 'nullable|exists:clients,id',
            'equipment_id' => 'nullable|exists:equipments,id',
            'description' => 'nullable|string',
            'priority' => 'required|in:1,2,3,4',
            'start_date' => 'nullable|date',
            'due_date' => 'nullable|date|after_or_equal:start_date',
            'photos' => 'nullable|array',
            'photos.*' => 'image|mimes:jpeg,png,jpg,gif|max:2048',
        ]);

        try {
            DB::beginTransaction();

            $photos = $job->photos ?? [];
            if ($request->hasFile('photos')) {
                foreach ($request->file('photos') as $photo) {
                    $path = $photo->store('job-photos', 'public');