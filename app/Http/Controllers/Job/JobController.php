<?php

namespace App\Http\Controllers\Job;

use App\Models\Job;
use App\Models\Item;
use App\Models\Task;
use App\Models\User;
use App\Models\Client;
use App\Models\JobType;
use App\Models\Employee;
use App\Models\JobItems;
use App\Models\Equipment;
use App\Models\JobOption;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\DB;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;

class JobController extends Controller
{
   public function index(Request $request)
{
    $companyId = Auth::user()->company_id;

    // Initialize query
    $query = Job::with(['jobType', 'client', 'equipment', 'jobEmployees.employee'])
        ->where('company_id', $companyId)
        ->where('active', true);

    // Get user role
    $userRole = Auth::user()->userRole->name ?? '';

    // Filter jobs based on user role
    switch($userRole) {
        case 'Supervisor':
            $query->where('created_by', Auth::id());
            break;

        case 'Employee':
            $employeeId = Auth::user()->employee_id;
            $query->whereHas('jobEmployees', function($q) use ($employeeId) {
                $q->where('employee_id', $employeeId);
            });
            break;

        case 'Engineer':
            // Show all active jobs within company (no additional filter needed)
            break;

        case 'Technical Officer':
            $query->where('assigned_user_id', Auth::id());
            break;

        default:
            // For any other role, show no jobs
            $query->where('id', 0);
            break;
    }

    // Handle sorting
    $sortBy = $request->input('sort_by', 'priority'); // Default to priority
    $sortOrder = $request->input('sort_order', 'asc'); // Default to ascending

    // Validate sort_by to prevent SQL injection
    $allowedSorts = ['id', 'priority', 'start_date', 'due_date'];
    if (!in_array($sortBy, $allowedSorts)) {
        $sortBy = 'priority';
    }

    // Apply sorting
    if ($sortBy === 'priority') {
        $query->orderBy('priority', $sortOrder)
              ->orderBy('start_date', 'asc'); // Secondary sort by start_date
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

    // Fetch filter options
    $jobTypes = JobType::all();
    $clients = Client::where('company_id', $companyId)->get();
    $equipments = Equipment::where('company_id', $companyId)->get();

    // Paginate results
    $jobs = $query->paginate(12);

    return view('jobs.index', compact('jobs', 'jobTypes', 'clients', 'equipments', 'sortBy', 'sortOrder'));
}

 public function create()
    {
        $companyId = Auth::user()->company_id;
        // return $companyId;
        $jobTypes = JobType::with(['jobOptions'])->where('active', true)->get();

        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        $employees = Employee::where('company_id', $companyId)->where('active', true)->get();

        // Get users where userRole is Technical officer and company is current company ,active =1
        $users = User::where('company_id', $companyId)
            ->whereHas('userRole', function ($query) {
                $query->where('name', 'Technical Officer');
            })
            ->where('active', true)
            ->get();

        return view('jobs.create', compact('jobTypes', 'clients', 'equipments', 'employees', 'users'));
    }

    // Add this new method to handle AJAX requests for job type options
    public function getJobTypeOptions($jobTypeId)
    {
        $jobType = JobType::with(['jobOptions'])->find($jobTypeId);

        if (!$jobType) {
            return response()->json(['error' => 'Job type not found'], 404);
        }

        return response()->json([
            'job_options' => $jobType->jobOptions->map(function($option) {
                return [
                    'id' => $option->id,
                    'name' => $option->name,
                    'description' => $option->description,
                    'option_type' => $option->option_type,
                    'required' => $option->required,
                    'options_json' => $option->options_json,

                ];
            })
        ]);
    }

    public function store(Request $request)
{
    // Build validation rules dynamically
    $rules = [

        'job_type_id' => 'required|exists:job_types,id',
        'client_id' => 'nullable|exists:clients,id',
        'equipment_id' => 'nullable|exists:equipments,id',
        'description' => 'nullable|string',
        'references' => 'nullable|string',
        'priority' => 'required|in:1,2,3,4',
        'assigned_user_id' => 'nullable|exists:users,id',
        'start_date' => 'nullable|date',
        'due_date' => 'nullable|date|after_or_equal:start_date',
        'photos' => 'nullable|array',
        'photos.*' => 'image|mimes:jpeg,png,jpg,gif|max:2048'
    ];

    // Add validation for job options if job_type_id is present
    if ($request->has('job_type_id') && $request->job_type_id) {
        $jobType = JobType::with('jobOptions')->find($request->job_type_id);
        if ($jobType) {
            foreach ($jobType->jobOptions as $option) {
                $fieldName = 'job_option_' . $option->id;

                if ($option->required) {
                    $rules[$fieldName] = 'required';
                }

                // Add specific validation based on option type
                switch ($option->option_type) {
                    case 'number':
                        $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'numeric';
                        break;
                    case 'date':
                        $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'date';
                        break;
                    case 'file':
                        $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'file|max:2048';
                        break;
                    case 'checkbox':
                        $rules[$fieldName] = 'nullable|boolean';
                        break;
                    case 'select':
                        // For equipment and client dropdowns
                        if ($option->id == 1) { // Equipment option
                            $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'exists:equipments,id';
                        } elseif ($option->id == 2) { // Client option
                            $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'exists:clients,id';
                        } else {
                            $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'string|max:255';
                        }
                        break;
                    default:
                        $rules[$fieldName] = ($option->required ? 'required|' : 'nullable|') . 'string|max:255';
                }
            }
        }
    }

    $request->validate($rules);

    $data = $request->all();
    $data['company_id'] = Auth::user()->company_id;
    $data['status'] = 'pending';
    $data['active'] = $request->has('is_active');
    $data['created_by'] = Auth::id();

    //assigned_user_id is assigned with the job ,he must be able to view job
    if ($request->has('assigned_user_id')) {
        $data['assigned_user_id'] = $request->input('assigned_user_id');
    }

    // Handle photo uploads
    if ($request->hasFile('photos')) {
        $photos = [];
        foreach ($request->file('photos') as $photo) {
            $photos[] = $photo->store('job_photos', 'public');
        }
        $data['photos'] = json_encode($photos);
    }

    // Handle job option values and map special ones to main fields
    $jobOptionValues = [];
    foreach ($request->all() as $key => $value) {
        if (strpos($key, 'job_option_') === 0) {
            $optionId = str_replace('job_option_', '', $key);

            // Map specific job options to main database fields
            if ($optionId == 1) { // Equipment option
                $data['equipment_id'] = $value;
            } elseif ($optionId == 2) { // Client option
                $data['client_id'] = $value;
            } else {
                // Handle file uploads for file type options
                if ($request->hasFile($key)) {
                    $jobOptionValues[$optionId] = $request->file($key)->store('job_option_files', 'public');
                } else {
                    $jobOptionValues[$optionId] = $value;
                }
            }
        }
    }

    if (!empty($jobOptionValues)) {
        $data['job_option_values'] = json_encode($jobOptionValues);
    }

    Job::create($data);

    return redirect()->route('jobs.index')->with('success', 'Job created successfully.');
}

    public function show(Job $job)
    {
        // Check if job belongs to current user's company
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $job->load(['jobType.jobOptions', 'client', 'equipment', 'jobEmployees.employee', 'jobEmployees.task']);
        $employees = Employee::where('company_id', Auth::user()->company_id)->where('active', true)->get();
        // tasks of that job
        $tasks = Task::where('job_id', $job->id)->where('active', true)->with('jobEmployees.employee')->get();
        $jobItems = JobItems::where('job_id', $job->id)
            ->where('active', true)
            ->get();
        return view('jobs.show', compact('job', 'employees', 'tasks', 'jobItems'));
    }

    public function edit(Job $job)
    {
        // Check if job belongs to current user's company
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $companyId = Auth::user()->company_id;
        $jobTypes = JobType::with('jobOptions')->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        return view('jobs.edit', compact('job', 'jobTypes', 'clients', 'equipments'));
    }

    public function update(Request $request, Job $job)
    {
        // Check if job belongs to current user's company
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $request->validate([

            'job_type_id' => 'required|exists:job_types,id',
            'client_id' => 'nullable|exists:clients,id',
            'equipment_id' => 'nullable|exists:equipments,id',
            'description' => 'nullable|string',
            'references' => 'nullable|string',
            'status' => 'required|in:pending,in_progress,on_hold,completed,cancelled',
            'priority' => 'required|in:1,2,3,4',
            'start_date' => 'nullable|date',
            'due_date' => 'nullable|date|after_or_equal:start_date',
            'completed_date' => 'nullable|date',
            'photos' => 'nullable|array',
            'photos.*' => 'image|mimes:jpeg,png,jpg,gif|max:2048'
        ]);

        $data = $request->all();
        $data['active'] = $request->has('is_active');
        $data['updated_by'] = Auth::id();

        // Handle photo uploads
        if ($request->hasFile('photos')) {
            // Delete old photos
            if ($job->photos) {
                $oldPhotos = json_decode($job->photos, true);
                foreach ($oldPhotos as $oldPhoto) {
                    Storage::disk('public')->delete($oldPhoto);
                }
            }

            $photos = [];
            foreach ($request->file('photos') as $photo) {
                $photos[] = $photo->store('job_photos', 'public');
            }
            $data['photos'] = json_encode($photos);
        }

        $job->update($data);

        return redirect()->route('jobs.index')->with('success', 'Job updated successfully.');
    }

    public function destroy(Job $job)
    {
        // Check if job belongs to current user's company
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

        $employees = Employee::where('company_id', Auth::user()->company_id)->where('active', true)->get();

        return view('tasks.create', compact('job', 'employees'));
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
            'status' => 'required|in:pending,in_progress,completed',
            'employee_ids' => 'required|array',
            'employee_ids.*' => 'exists:employees,id',
            'notes' => 'nullable|string',
        ]);

        $task = Task::create([

            'task' => $request->task,
            'description' => $request->description,
            'status' => $request->status,
            'active' => $request->has('is_active'),
            'created_by' => Auth::id(),
        ]);

        foreach ($request->employee_ids as $employeeId) {
            $job->jobEmployees()->create([
                'employee_id' => $employeeId,
                'task_id' => $task->id,
                'start_date' => $request->start_date,
                'end_date' => $request->end_date,
                'duration_in_days' => $request->start_date && $request->end_date ?
                    \Carbon\Carbon::parse($request->start_date)->diffInDays(\Carbon\Carbon::parse($request->end_date)) + 1 : null,
                'status' => 'pending',
                'notes' => $request->notes,
                'created_by' => Auth::id(),
                'updated_by' => Auth::id(),
            ]);
        }

        return redirect()->route('jobs.show', $job)->with('success', 'Task created and employees assigned successfully.');
    }

    public function editTask(Job $job, Task $task)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $employees = Employee::where('company_id', Auth::user()->company_id)->where('active', true)->get();

        return view('tasks.edit', compact('job', 'task', 'employees'));
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
            'status' => 'required|in:pending,in_progress,completed',
            'employee_ids' => 'required|array',
            'employee_ids.*' => 'exists:employees,id',
            'notes' => 'nullable|string',
        ]);

        $task->update([
            'task' => $request->task,
            'description' => $request->description,
            'status' => $request->status,
            'active' => $request->has('is_active'),
            'updated_by' => Auth::id(),
        ]);

        // Delete existing job_employee records for this task
        $job->jobEmployees()->where('task_id', $task->id)->delete();

        // Create new job_employee records
        foreach ($request->employee_ids as $employeeId) {
            $job->jobEmployees()->create([
                'employee_id' => $employeeId,
                'task_id' => $task->id,
                'start_date' => $request->start_date,
                'end_date' => $request->end_date,
                'duration_in_days' => $request->start_date && $request->end_date ?
                    \Carbon\Carbon::parse($request->start_date)->diffInDays(\Carbon\Carbon::parse($request->end_date)) + 1 : null,
                'status' => 'pending',
                'notes' => $request->notes,
                'created_by' => Auth::id(),
                'updated_by' => Auth::id(),
            ]);
        }

        return redirect()->route('jobs.show', $job)->with('success', 'Task updated successfully.');
    }

    public function destroyTask(Job $job, Task $task)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $task->update(['active' => false, 'updated_by' => Auth::id()]);
        $job->jobEmployees()->where('task_id', $task->id)->update(['active' => false, 'updated_by' => Auth::id()]);

        return redirect()->route('jobs.show', $job)->with('success', 'Task deleted successfully.');
    }

 public function addItems(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $items = Item::where('company_id', Auth::user()->company_id)
                     ->where('active', true)
                     ->get();

        // Get all current job items with job id 
        $jobItems = JobItems::where('job_id', $job->id)
            ->where('active', true)
            ->with('item')  // Load the related item model
            ->get(['id', 'job_id', 'item_id', 'quantity', 'notes', 'issue_description', 
                   'custom_item_description', 'added_by', 'added_at', 'addition_stage', 'active']);

        // Get users with approval role whose role is admin,engineer
        $approvalUsers = User::where('company_id', Auth::user()->company_id)
            ->whereHas('userRole', function ($query) {
                $query->whereIn('name', ['Engineer', 'admin']);
            })
            ->where('active', true)
            ->get();
        return view('jobs.items.add', compact('job', 'items', 'jobItems', 'approvalUsers'));
    }

    /**
     * Store items added to a job
     */
public function storeItems(Request $request, Job $job)
{
    if ($job->company_id !== Auth::user()->company_id) {
        abort(403);
    }

    $request->validate([
        'issue_description' => 'required|string|max:1000',
        'items' => 'nullable|array',
        'items.*.item_id' => 'nullable|exists:items,id',
        'items.*.quantity' => 'nullable|numeric|min:0.01',
        'items.*.notes' => 'nullable|string|max:500',
        'new_items' => 'nullable|array',
        'new_items.*.description' => 'nullable|string|max:500',
        'new_items.*.quantity' => 'nullable|numeric|min:0.01',
        'close_job' => 'nullable|boolean',
        'request_approval_from' => 'nullable|exists:users,id',
    ]);

    // If closing job as minor issue
    if ($request->has('close_job') && $request->close_job) {
        $job->update([
            'status' => 'completed',
            'approval_status' => 'approved',
            'approved_by' => Auth::id(),
            'approved_at' => now(),
            'approval_notes' => 'Closed as minor issue: ' . $request->issue_description,
            'completed_date' => now(),
            'updated_by' => Auth::id(),
        ]);

        return redirect()->route('jobs.show', $job)->with('success', 'Job closed successfully as minor issue.');
    }

    // Check if job is already in approval process
    $isInApprovalProcess = $job->approval_status === 'requested';
    
    // Get current job items to check for existing ones
    $currentJobItems = DB::table('job_items')
        ->where('job_id', $job->id)
        ->where('active', true)
        ->get()
        ->keyBy('item_id');

    // Store existing items
    if ($request->has('items')) {
        foreach ($request->items as $itemData) {
            if (!empty($itemData['item_id']) && !empty($itemData['quantity'])) {
                
                $itemId = $itemData['item_id'];
                
                // Check if this item already exists for this job
                if ($currentJobItems->has($itemId)) {
                    // Update existing item: sum the quantities
                    $existingItem = $currentJobItems->get($itemId);
                    $newQuantity = $existingItem->quantity + $itemData['quantity'];

                    DB::table('job_items')
                        ->where('id', $existingItem->id)
                        ->update([
                            'quantity' => $newQuantity,
                            'notes' => $itemData['notes'] ?? $existingItem->notes,
                            'issue_description' => $request->issue_description,
                            'added_by' => Auth::id(), 
                            'added_at' => now(),      
                            'updated_by' => Auth::id(),
                            'updated_at' => now(),
                        ]);
                } else {

                    DB::table('job_items')->insert([
                        'job_id' => $job->id,
                        'item_id' => $itemId,
                        'quantity' => $itemData['quantity'],
                        'notes' => $itemData['notes'] ?? null,
                        'issue_description' => $request->issue_description,
                        'added_by' => Auth::id(),
                        'added_at' => now(),
                        'addition_stage' => 'job_approval',
                        'active' => true,
                        'created_by' => Auth::id(),
                        'updated_by' => Auth::id(),
                        'created_at' => now(),
                        'updated_at' => now(),
                    ]);
                }
            }
        }
    }

    // Store new item descriptions (items not in inventory)
    if ($request->has('new_items')) {
        foreach ($request->new_items as $newItem) {
            if (!empty($newItem['description']) && !empty($newItem['quantity'])) {
                
               
                
                DB::table('job_items')->insert([
                    'job_id' => $job->id,
                    'item_id' => null, // null for custom items
                    'custom_item_description' => $newItem['description'],
                    'quantity' => $newItem['quantity'],
                    'issue_description' => $request->issue_description,
                    'added_by' => Auth::id(),
                    'added_at' => now(),
                    'addition_stage' => 'job_approval',
                    'active' => true,
                    'created_by' => Auth::id(),
                    'updated_by' => Auth::id(),
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }
        }
    }

    // Handle approval request logic
    if ($request->has('request_approval_from') && $request->request_approval_from) {
        // Only change approval status if not already in approval process
        if (!$isInApprovalProcess) {
            $job->update([
                'approval_status' => 'requested',
                'request_approval_from' => $request->request_approval_from,
                'updated_by' => Auth::id(),
            ]);
            
            $message = 'Items added and approval requested successfully.';
        } else {
            // Job already in approval, just update the timestamp
            $job->update([
                'updated_by' => Auth::id(),
            ]);
            
            $message = 'Additional items added to existing approval request.';
        }
    } else {
        // No approval requested, just update the job
        $job->update([
            'updated_by' => Auth::id(),
        ]);
        
        if ($isInApprovalProcess) {
            $message = 'Additional items added. Job remains in approval process.';
        } else {
            $message = 'Items added to job successfully.';
        }
    }

    return redirect()->route('jobs.show', $job)->with('success', $message);
}
    /**
     * Show job approval interface
     */
    public function showApproval(Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Check if user has approval rights
        $userRole = Auth::user()->userRole->name ?? '';
        if (!in_array($userRole, ['Engineer', 'admin'])) {
            abort(403, 'You do not have permission to approve jobs.');
        }

        $job->load(['jobType', 'client', 'equipment']);

        // Get job items with their details
        $jobItems = $job->items()->withPivot([
            'quantity',
            'notes',
            'issue_description',
            'custom_item_description',
            'added_by',
            'added_at',
            'addition_stage',
            'active'
        ])->where('job_items.active', true)->get();

        // Get all items for potential editing
        $items = Item::where('company_id', Auth::user()->company_id)
                     ->where('active', true)
                     ->get();

        return view('jobs.approve', compact('job', 'jobItems', 'items'));
    }

    /**
     * Process job approval
     */
    public function processApproval(Request $request, Job $job)
    {
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Check if user has approval rights
        $userRole = Auth::user()->userRole->name ?? '';
        if (!in_array($userRole, ['Engineer', 'admin'])) {
            abort(403, 'You do not have permission to approve jobs.');
        }

        $request->validate([
            'action' => 'required|in:approve,reject',
            'approval_notes' => 'nullable|string|max:1000',
            'items' => 'nullable|array',
            'items.*.item_id' => 'nullable|exists:items,id',
            'items.*.quantity' => 'nullable|numeric|min:0.01',
            'items.*.notes' => 'nullable|string|max:500',
            'new_items' => 'nullable|array',
            'new_items.*.description' => 'nullable|string|max:500',
            'new_items.*.quantity' => 'nullable|numeric|min:0.01',
        ]);

        if ($request->action === 'approve') {
            // Update existing items if provided
            if ($request->has('items')) {
                foreach ($request->items as $itemId => $itemData) {
                    if (!empty($itemData['quantity'])) {
                        $job->items()->updateExistingPivot($itemId, [
                            'quantity' => $itemData['quantity'],
                            'notes' => $itemData['notes'] ?? null,
                            'addition_stage' => 'job_approval',
                            'updated_by' => Auth::id(),
                        ]);
                    }
                }
            }

            // Add new items if provided during approval
            if ($request->has('new_items')) {
                foreach ($request->new_items as $newItem) {
                    if (!empty($newItem['description']) && !empty($newItem['quantity'])) {
                        $job->items()->attach(null, [
                            'quantity' => $newItem['quantity'],
                            'custom_item_description' => $newItem['description'],
                            'added_by' => Auth::id(),
                            'added_at' => now(),
                            'addition_stage' => 'job_approval',
                            'active' => true,
                            'created_by' => Auth::id(),
                            'updated_by' => Auth::id(),
                        ]);
                    }
                }
            }

            $job->update([
                'approval_status' => 'approved',
                'approved_by' => Auth::id(),
                'approved_at' => now(),
                'approval_notes' => $request->approval_notes,
                'status' => 'pending', // Move to pending for task assignment
                'updated_by' => Auth::id(),
            ]);

            return redirect()->route('jobs.tasks.create', $job)->with('success', 'Job approved successfully. You can now add tasks.');
        } else {
            // Reject the job
            $job->update([
                'approval_status' => 'rejected',
                'rejected_by' => Auth::id(),
                'rejected_at' => now(),
                'rejection_notes' => $request->approval_notes,
                'updated_by' => Auth::id(),
            ]);

            return redirect()->route('jobs.index')->with('success', 'Job rejected successfully.');
        }
    }
     public function copy(Job $job)
    {

        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $companyId = Auth::user()->company_id;
        $jobTypes = JobType::with('jobOptions')->where('active', true)->get();
        $clients = Client::where('company_id', $companyId)->where('active', true)->get();
        $equipments = Equipment::where('company_id', $companyId)->where('active', true)->get();

        // Decode job option values for editing
        $jobOptionValues = $job->job_option_values ? json_decode($job->job_option_values, true) : [];

        return view('jobs.copy', compact('job', 'jobTypes', 'clients', 'equipments', 'jobOptionValues'));
    }

    public function storeCopy(Request $request, Job $job)
    {


        // Get job type and its options for validation
        $jobType = null;
        if ($request->has('job_type_id') && $request->job_type_id) {
            $jobType = JobType::with('jobOptions')->find($request->job_type_id);
        }

        // Build validation rules
        $rules = $this->getValidationRules($jobType);
        $request->validate($rules);

        // Prepare job data
        $jobData = $this->prepareJobData($request);

        // Handle job option values
        $jobOptionValues = $this->processJobOptionValues($request, $jobType);
        if (!empty($jobOptionValues)) {
            $jobData['job_option_values'] = $jobOptionValues;
        }

        // Copy photos from original job
        if ($job->photos) {
            $jobData['photos'] = $job->photos; // Copy JSON-encoded photos
        }

        // Create the new job
        $newJob = Job::create($jobData);

        // Copy tasks from original job
        $tasks = Task::where('job_id', $job->id)->where('active', true)->get();
        foreach ($tasks as $task) {
            $newTask = $task->replicate();
            $newTask->job_id = $newJob->id;
            $newTask->created_by = Auth::id();
            $newTask->save();

            // Copy job employees for the task
            $jobEmployees = $job->jobEmployees()->where('task_id', $task->id)->get();
            foreach ($jobEmployees as $jobEmployee) {
                $newJob->jobEmployees()->create([
                    'employee_id' => $jobEmployee->employee_id,
                    'task_id' => $newTask->id,
                    'start_date' => $jobEmployee->start_date,
                    'end_date' => $jobEmployee->end_date,
                    'duration_in_days' => $jobEmployee->duration_in_days,
                    'status' => $jobEmployee->status,
                    'notes' => $jobEmployee->notes,
                    'created_by' => Auth::id(),
                    'updated_by' => Auth::id(),
                ]);
            }
        }

        return redirect()->route('jobs.index')->with('success', 'Job copied successfully as a new job.');
    }

    public function extendTask(Job $job)
    {


        $tasks = Task::where('job_id', $job->id)->where('active', true)->with('jobEmployees.employee')->get();
        return view('tasks.extend-task', compact('job', 'tasks'));
    }

    public function storeExtendTask(Request $request, Job $job)
    {


        $request->validate([
            'task_id' => 'required|exists:tasks,id',
            'new_end_date' => 'required|date|after_or_equal:start_date',
        ]);

        // Find the task and its job employees
        $task = Task::where('job_id', $job->id)->findOrFail($request->task_id);
        $jobEmployees = $job->jobEmployees()->where('task_id', $task->id)->get();

        // Calculate new duration
        $newEndDate = \Carbon\Carbon::parse($request->new_end_date);
        $startDate = $jobEmployees->first()->start_date ? \Carbon\Carbon::parse($jobEmployees->first()->start_date) : null;
        $durationInDays = $startDate ? $startDate->diffInDays($newEndDate) + 1 : null;

        // Get job type for validation
        $jobType = JobType::with('jobOptions')->find($job->job_type_id);

        // Create new job with updated due date
        $jobData = [

            'job_type_id' => $job->job_type_id,
            'client_id' => $job->client_id,
            'equipment_id' => $job->equipment_id,
            'description' => $job->description,
            'references' => $job->references,
            'priority' => $job->priority,
            'start_date' => $job->start_date,
            'due_date' => $newEndDate->format('Y-m-d'),
            'active' => true,
            'status' => $job->status,
            'company_id' => Auth::user()->company_id,
            'created_by' => Auth::id(),
            'photos' => $job->photos,
            'job_option_values' => $job->job_option_values,
        ];

        $newJob = Job::create($jobData);

        // Copy all tasks, updating the selected task's duration
        $tasks = Task::where('job_id', $job->id)->where('active', true)->get();
        foreach ($tasks as $existingTask) {
            $newTask = $existingTask->replicate();
            $newTask->job_id = $newJob->id;
            $newTask->created_by = Auth::id();

            if ($existingTask->id == $request->task_id) {
                $newTask->end_date = $newEndDate->format('Y-m-d');
            }

            $newTask->save();

            // Copy job employees, updating duration for the selected task
            $existingJobEmployees = $job->jobEmployees()->where('task_id', $existingTask->id)->get();
            foreach ($existingJobEmployees as $jobEmployee) {
                $newJob->jobEmployees()->create([
                    'employee_id' => $jobEmployee->employee_id,
                    'task_id' => $newTask->id,
                    'start_date' => $jobEmployee->start_date,
                    'end_date' => ($existingTask->id == $request->task_id) ? $newEndDate->format('Y-m-d') : $jobEmployee->end_date,
                    'duration_in_days' => ($existingTask->id == $request->task_id) ? $durationInDays : $jobEmployee->duration_in_days,
                    'status' => $jobEmployee->status,
                    'notes' => $jobEmployee->notes,
                    'created_by' => Auth::id(),
                    'updated_by' => Auth::id(),
                ]);
            }
        }

        return redirect()->route('jobs.index')->with('success', 'New job created with extended task duration.');
    }
}
