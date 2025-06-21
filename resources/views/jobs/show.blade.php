@extends('layouts.app')

@section('content')
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <div class="d-component-title">
                                <span>Job Details: {{ $job->id }}</span>
                            </div>
                            <div>
                                @if($job->status === 'closed')
                                    <a href="{{ route('jobs.copy', $job) }}" class="btn btn-warning btn-sm">
                                        <i class="fas fa-copy"></i> Copy Job
                                    </a>
                                @else
                                    <a href="{{ route('jobs.copy', $job) }}" class="btn btn-warning btn-sm">
                                        <i class="fas fa-copy"></i> Copy Job
                                    </a>

                                    @if(in_array(auth()->user()->userRole->name, ['Engineer', 'admin']) && $job->status === 'completed')
                                        <a href="{{ route('jobs.review', $job) }}" class="btn btn-sm btn-primary">
                                            <i class="fas fa-clipboard-check"></i> Review & Close Job
                                        </a>
                                    @endif

                                    @if ($job->approval_status == 'requested')
                                        @if(auth()->user()->userRole->name=='Engineer')
                                            <a href="{{ route('jobs.items.show-approval', $job) }}" class="btn btn-success btn-sm">
                                                <i class="fas fa-check"></i> Approve Job
                                            </a>
                                        @endif
                                    @endif

                                    @if ($job->approval_status == 'approved' && $job->status !='completed')
                                        @if(auth()->user()->userRole->name=='Engineer')
                                            <a href="{{ route('jobs.tasks.create', $job) }}" class="btn btn-primary btn-sm">
                                                <i class="fas fa-plus"></i> Add Task
                                            </a>
                                        @endif
                                    @endif

                                    @if ($job->jobEmployees->count() > 0)
                                        <a href="{{ route('jobs.extend-task', $job) }}" class="btn btn-warning btn-sm">
                                            <i class="fas fa-clock"></i> Extend Task
                                        </a>
                                    @endif

                                    @if(in_array(auth()->user()->userRole->name ?? '', ['Supervisor', 'Technical Officer', 'Engineer']))
                                        <a href="{{ route('tasks.extension.index') }}" class="btn btn-info btn-sm">
                                            <i class="fas fa-clipboard-list"></i> Extension Requests
                                        </a>
                                    @endif

                                    @if ($job->assigned_user_id == auth()->user()->id && $job->status !='completed' && $job->status != 'cancelled' && $job->approval_status !='approved')
                                        <a href="{{ route('jobs.items.add', $job) }}" class="btn btn-primary btn-sm">
                                            <i class="fas fa-plus"></i> Add Item
                                        </a>
                                    @endif
                                @endif

                                <a href="{{ route('jobs.index') }}" class="btn btn-secondary btn-sm">
                                    <i class="fas fa-arrow-left"></i> Back to Jobs
                                </a>
                            </div>
                        </div>
                    </div>

                    <div class="card-body">
                        @if (session('success'))
                            <div class="alert alert-success mt-3">
                                {{ session('success') }}
                            </div>
                        @endif
                        @if (session('error'))
                            <div class="alert alert-danger mt-3">
                                {{ session('error') }}
                            </div>
                        @endif

                        <!-- Job Details -->
                      <!-- Job Details -->
<div class="d-component-container mb-4">
    <h5>Job Information</h5>

    <!-- Basic Information -->
    <div class="row mb-3">
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">JOB ID</label>
                <div class="fs-5 fw-semibold">#{{ $job->id }}</div>
            </div>
        </div>
        @if($job->jobType)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">JOB TYPE</label>
                <div>
                    <span class="badge" style="background-color: {{ $job->jobType->color ?? '#6c757d' }};">
                        {{ $job->jobType->name }}
                    </span>
                </div>
            </div>
        </div>
        @endif
        @if($job->client)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">CLIENT</label>
                <div class="fw-semibold">{{ $job->client->name }}</div>
            </div>
        </div>
        @endif
        @if($job->equipment)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">EQUIPMENT</label>
                <div class="fw-semibold">{{ $job->equipment->name }}</div>
            </div>
        </div>
        @endif
    </div>

    <!-- Status Information -->
    <div class="row mb-3">
        @if($job->status)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">STATUS</label>
                <div>
                    @php
                        $statusColors = [
                            'pending' => 'warning',
                            'in_progress' => 'primary',
                            'on_hold' => 'info',
                            'completed' => 'success',
                            'cancelled' => 'danger'
                        ];
                    @endphp
                    <span class="badge bg-{{ $statusColors[$job->status] ?? 'secondary' }}">
                        {{ ucfirst(str_replace('_', ' ', $job->status)) }}
                    </span>
                </div>
            </div>
        </div>
        @endif
        @if($job->approval_status)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">APPROVAL STATUS</label>
                <div>
                    <span class="badge bg-{{ $job->approval_status == 'requested' ? 'warning' : 'success' }}">
                        {{ ucfirst($job->approval_status) }}
                    </span>
                </div>
            </div>
        </div>
        @endif
        @if($job->priority)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">PRIORITY</label>
                <div>
                    @php
                        $priorityColors = [
                            '1' => 'danger',
                            '2' => 'warning',
                            '3' => 'info',
                            '4' => 'secondary',
                        ];
                        $priorityLabels = [
                            '1' => 'High',
                            '2' => 'Medium',
                            '3' => 'Low',
                            '4' => 'Very Low',
                        ];
                    @endphp
                    <span class="badge bg-{{ $priorityColors[$job->priority] }}">
                        {{ $priorityLabels[$job->priority] }}
                    </span>
                </div>
            </div>
        </div>
        @endif
        @if($job->assignedUser)
        <div class="col-md-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">ASSIGNED TO</label>
                <div class="fw-semibold">{{ $job->assignedUser->name }}</div>
            </div>
        </div>
        @endif
    </div>

    <!-- Date Information -->
    <div class="row mb-3">
        @if($job->created_at)
        <div class="col-md-4">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">CREATED DATE</label>
                <div class="fw-semibold">{{ $job->created_at->format('M d, Y') }}</div>
            </div>
        </div>
        @endif
        @if($job->start_date)
        <div class="col-md-4">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">START DATE</label>
                <div class="fw-semibold">{{ $job->start_date->format('M d, Y') }}</div>
            </div>
        </div>
        @endif
        @if($job->due_date)
        <div class="col-md-4">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">DUE DATE</label>
                <div class="fw-semibold {{ $job->due_date->isPast() && $job->status !== 'completed' ? 'text-danger' : '' }}">
                    {{ $job->due_date->format('M d, Y') }}
                    @if($job->due_date->isPast() && $job->status !== 'completed')
                        <small class="d-block text-danger">
                            <i class="fas fa-exclamation-triangle"></i> Overdue
                        </small>
                    @endif
                </div>
            </div>
        </div>
        @endif
    </div>

    <!-- Additional Information -->
    @if($job->description || $job->references)
    <div class="row">
        @if($job->description)
        <div class="col-md-6 mb-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">DESCRIPTION</label>
                <div class="fw-normal">{{ $job->description }}</div>
            </div>
        </div>
        @endif
        @if($job->references)
        <div class="col-md-6 mb-3">
            <div class="border p-3 h-100">
                <label class="form-label fw-bold text-muted small">REFERENCES</label>
                <div class="fw-normal">{{ $job->references }}</div>
            </div>
        </div>
        @endif




    </div>
    @endif
       <div class="mt-3 mb-3">
        <a href="{{ route('jobs.history.index', $job->id) }}" class="btn btn-outline-info btn-sm">
            <i class="fas fa-history"></i> View Job History
        </a>
    </div>
    </div>



  @if($job->status === 'closed')
  <div class="d-component-container mb-4">
    <div class="alert alert-success">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <i class="fas fa-check-circle"></i>
                <strong>Job Closed</strong>
                <p class="mb-0">This job has been reviewed and closed by {{ $job->reviewer->name ?? 'Engineer' }}
                    on {{ $job->closed_at ? $job->closed_at->format('M d, Y') : 'N/A' }}.</p>
                @if($job->review_notes)
                    <small class="text-muted">Review Notes: {{ $job->review_notes }}</small>
                @endif
            </div>
            <div>
                <!-- Copy Job Button for closed jobs -->
                <a href="#" class="btn btn-outline-primary btn-sm" onclick="copyJob({{ $job->id }})">
                    <i class="fas fa-copy"></i> Copy as New Job
                </a>
            </div>
        </div>
    </div>
    </div>
@endif

                        <!-- Photos -->
                        @if ($job->photos)
                            <div class="d-component-container mb-4">
                                <h5>Photos</h5>
                                <div class="row">
                                    @foreach (json_decode($job->photos, true) as $photo)
                                        <div class="col-md-3 mb-2">
                                            <img src="{{ Storage::url($photo) }}" alt="Job Photo" class="img-thumbnail"
                                                style="max-height: 150px;">
                                        </div>
                                    @endforeach
                                </div>
                            </div>
                        @endif

                        {{-- Items card--}}
                        @if($jobItems->count() > 0)
                            <div class="d-component-container mb-4">
                                <h5>Items</h5>
                                {{-- for already  registered items  the item_id exists and custom_item_description is null ,
                                for not registered items ,item_id is null and custom_item_description exists--}}
                                <div class="table-responsive table-compact">
                                    <table class="table table-bordered">
                                        <thead>
                                            <tr>
                                                <th>Item</th>
                                                <th>Unit</th>
                                                <th>Quantity</th>
                                                <th>Notes</th>
                                                <th>Added by</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            @if($jobItems->whereNotNull('item_id')->whereNull('custom_item_description')->count() > 0)
                                                @foreach ($jobItems->whereNotNull('item_id')->whereNull('custom_item_description') as $item)
                                                    <tr>
                                                        <td>{{ $item->item->name }}</td>
                                                        <td>{{ $item->item->unit }}</td>
                                                        <td>{{ $item->quantity }}</td>
                                                        <td>{{ $item->notes }}</td>
                                                        @php
                                                        //   get the user name whose id is item->added_by
                                                        $added_by = \App\Models\User::find($item->added_by);
                                                        @endphp
                                                        <td>{{ $added_by->name ?? 'N/A' }}</td>
                                                    </tr>
                                                @endforeach
                                            @endif
                                        </tbody>
                                    </table>
                                </div>
                                @if($jobItems->whereNotNull('custom_item_description')->whereNull('item_id')->count() > 0)
                                    <h6 class="mt-4">New Items</h6>
                                    <div class="table-responsive table-compact">
                                        <table class="table table-bordered">
                                            <thead>
                                                <tr>
                                                    <th>Item</th>
                                                    <th>Quantity</th>
                                                    <th>Notes</th>
                                                    <th>Added by</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                @foreach ($jobItems->whereNotNull('custom_item_description')->whereNull('item_id') as $item)
                                                    <tr>
                                                        <td>{{ $item->custom_item_description }}</td>
                                                        <td>{{ $item->quantity }}</td>
                                                        <td>{{ $item->notes }}</td>
                                                        @php
                                                        $added_by = \App\Models\User::find($item->added_by);
                                                        @endphp
                                                        <td>{{ $added_by->name ?? 'N/A' }}</td>
                                                    </tr>
                                                @endforeach
                                            </tbody>
                                        </table>
                                    </div>
                                @endif
                            </div>
                        @endif

  <!-- Tasks Card -->
<div class="d-component-container mb-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h5>Tasks</h5>
        {{-- NEW: Employee extension request link --}}
        @if(auth()->user()->userRole->name == 'Employee')
            <div>
                <a href="{{ route('tasks.extension.my-requests') }}" class="btn btn-info btn-sm">
                    <i class="fas fa-history"></i> My Extension Requests
                </a>
            </div>
        @endif
    </div>
    <div class="table-responsive table-compact">
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>Task Name</th>
                    <th>Description</th>
                    <th>Assigned Employees</th>
                    <th>Status</th>
                    <th>Start Date</th>
                    <th>End Date</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                @php
                    $currentEmployee = \App\Models\Employee::where('user_id', auth()->id())->first();
                    $isEmployee = auth()->user()->userRole->name === 'Employee';
                    $jobEmployeesGrouped = $isEmployee && $currentEmployee
                        ? $job->jobEmployees->where('employee_id', $currentEmployee->id)->groupBy('task_id')
                        : $job->jobEmployees->groupBy('task_id');
                @endphp
                @forelse ($jobEmployeesGrouped as $taskId => $jobEmployees)
                    @php
                        $task = $job->jobEmployees->where('task_id', $taskId)->first()->task;
                        // Check if current user is assigned to this task
                        $currentEmployee = \App\Models\Employee::where('user_id', auth()->id())->first();
                        $isAssignedToTask = $currentEmployee && $jobEmployees->contains('employee_id', $currentEmployee->id);

                        // Check for pending extension requests
                        $pendingExtension = null;
                        if($currentEmployee) {
                            $pendingExtension = \App\Models\TaskExtensionRequest::where('task_id', $task->id)
                                ->where('employee_id', $currentEmployee->id)
                                ->where('status', 'pending')
                                ->first();
                        }
                    @endphp
                    <tr>
                        <td>{{ $task->task }}</td>
                        <td>{{ $task->description ?? 'N/A' }}</td>
                        <td>
                            @foreach ($jobEmployees as $je)
                                {{ $je->employee->name ?? 'N/A' }}@if (!$loop->last)
                                    ,
                                @endif
                            @endforeach
                        </td>
                        <td>
                            <span class="badge bg-{{ $statusColors[$task->status] ?? 'secondary' }}">
                                {{ ucfirst(str_replace('_', ' ', $task->status)) }}
                            </span>
                        </td>
                        <td>{{ $jobEmployees->first()->start_date ? $jobEmployees->first()->start_date->format('Y-m-d') : 'N/A' }}
                        </td>
                        <td>{{ $jobEmployees->max('end_date') ? \Carbon\Carbon::parse($jobEmployees->max('end_date'))->format('Y-m-d') : 'N/A' }}
                        </td>
                        <td>
                            @php
                                $currentUserEmployee = Auth::user()->employee ?? null;
                                $isAssignedToTask = false;
                                $userJobEmployee = null;

                                if ($currentUserEmployee) {
                                    $userJobEmployee = $jobEmployees->where('employee_id', $currentUserEmployee->id)->first();
                                    $isAssignedToTask = $userJobEmployee !== null;
                                }
                            @endphp

                            @if(Auth::user()->userRole->name === 'Employee' && $isAssignedToTask)
                                <!-- Employee Task Actions -->
                                <div class="btn-group" role="group">
                                    @if($task->status === 'pending')
                                        <form action="{{ route('tasks.start', $task) }}" method="POST" style="display: inline;">
                                            @csrf
                                            <button type="submit" class="btn btn-primary btn-sm" onclick="return confirm('Are you sure you want to start this task?')">
                                                <i class="fas fa-play"></i> Start
                                            </button>
                                        </form>
                                    @elseif($task->status === 'in_progress')
                                        <form action="{{ route('tasks.complete', $task) }}" method="POST" style="display: inline;">
                                            @csrf
                                            <button type="submit" class="btn btn-success btn-sm" onclick="return confirm('Are you sure you want to complete this task?')">
                                                <i class="fas fa-check"></i> Complete
                                            </button>
                                        </form>
                                        <a href="{{ route('tasks.extension.create', $task) }}" class="btn btn-warning btn-sm" title="Request Extension">
                                            <i class="fas fa-clock"></i>
                                        </a>
                                    @elseif($task->status === 'completed')
                                        <span class="badge bg-success">
                                            <i class="fas fa-check-circle"></i> Completed
                                        </span>
                                    @endif
                                </div>
                            @else
                                <!-- Non-employee or unassigned users see view/edit options -->
                                @if(in_array(Auth::user()->userRole->name, ['Engineer', 'Supervisor', 'Technical Officer', 'admin']))
                                    <div class="btn-group" role="group">
                                        {{-- <a href="{{ route('tasks.show', ['job' => $job->id, 'task' => $task->id]) }}" class="btn btn-info btn-sm" title="View Details">
                                            <i class="fas fa-eye"></i>
                                        </a> --}}
                                        @if($task->status !== 'completed' && in_array(Auth::user()->userRole->name, ['Engineer', 'Supervisor']))
                                            <a href="{{ route('jobs.tasks.edit', ['job' => $job->id, 'task' => $task->id]) }}" class="btn btn-secondary btn-sm" title="Edit Task">
                                                <i class="fas fa-edit"></i>
                                            </a>
                                        @endif
                                    </div>
                                @else
                                    <span class="text-muted">-</span>
                                @endif
                            @endif
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="text-center">No tasks found.</td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>
</div>
                        </div>


                        <div class="row me-2" style="margin-left:5px;">
    <div class="col-12">
        @include('jobs.components.timeline')
    </div>
</div>
                    </div>
                </div>
            </div>
        </div>
@endsection
