{{-- resources/views/jobs/history/index.blade.php --}}
@extends('layouts.app')

@section('title', 'Job History - Job #' . $job->id)

@section('content')
<div class="container-fluid">
    <!-- Job Header -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <h4 class="mb-0">
                            <i class="fas fa-history text-primary"></i>
                            Job History - Job #{{ $job->id }}
                        </h4>
                        <small class="text-muted">{{ $job->description }}</small>
                    </div>
                    <div class="btn-group">
                        <a href="{{ route('jobs.show', $job) }}" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left"></i> Back to Job
                        </a>
                        <div class="btn-group" role="group">
                            <button type="button" class="btn btn-success dropdown-toggle" data-bs-toggle="dropdown">
                                <i class="fas fa-download"></i> Export
                            </button>
                            <ul class="dropdown-menu">
                                <li>
                                    <a class="dropdown-item" href="{{ route('jobs.history.export.pdf', $job) }}{{ request()->getQueryString() ? '?' . request()->getQueryString() : '' }}">
                                        <i class="fas fa-file-pdf text-danger"></i> Export as PDF
                                    </a>
                                </li>
                                <li>
                                    <a class="dropdown-item" href="{{ route('jobs.history.export.word', $job) }}{{ request()->getQueryString() ? '?' . request()->getQueryString() : '' }}">
                                        <i class="fas fa-file-word text-primary"></i> Export as Word
                                    </a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Job Summary and Statistics -->
    <div class="row mb-4">
        <div class="col-lg-8">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-info-circle"></i> Job Information</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Job Type:</strong> {{ $job->jobType->name ?? 'N/A' }}</p>
                            <p><strong>Client:</strong> {{ $job->client->name ?? 'N/A' }}</p>
                            <p><strong>Equipment:</strong> {{ $job->equipment->name ?? 'N/A' }}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Status:</strong>
                                <span class="badge badge-{{ $job->status === 'completed' ? 'success' : ($job->status === 'cancelled' ? 'danger' : 'warning') }}">
                                    {{ ucfirst($job->status) }}
                                </span>
                            </p>
                            <p><strong>Priority:</strong>
                                <span class="badge badge-{{ $job->priority == 1 ? 'danger' : ($job->priority == 2 ? 'warning' : 'info') }}">
                                    Priority {{ $job->priority }}
                                </span>
                            </p>
                            <p><strong>Created:</strong> {{ $job->created_at->format('M d, Y H:i') }}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-chart-bar"></i> Activity Statistics</h5>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-6">
                            <div class="stat-item">
                                <h4 class="text-primary">{{ $stats['total_activities'] }}</h4>
                                <small class="text-muted">Total Activities</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-item">
                                <h4 class="text-success">{{ $stats['major_activities'] }}</h4>
                                <small class="text-muted">Major Activities</small>
                            </div>
                        </div>
                    </div>
                    <hr>
                    <div class="row text-center">
                        <div class="col-6">
                            <div class="stat-item">
                                <h4 class="text-info">{{ $stats['users_involved'] }}</h4>
                                <small class="text-muted">Users Involved</small>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-item">
                                <small class="text-muted">Last Activity</small>
                                <div class="text-dark">
                                    {{ $stats['last_activity'] ? $stats['last_activity']->diffForHumans() : 'N/A' }}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-filter"></i> Filters
                        <button class="btn btn-sm btn-outline-secondary float-right" type="button" data-bs-toggle="collapse" data-bs-target="#filtersCollapse">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </h5>
                </div>
                <div class="collapse {{ request()->hasAny(['category', 'type', 'user_id', 'date_from', 'date_to', 'major_only']) ? 'show' : '' }}" id="filtersCollapse">
                    <div class="card-body">
                        <form method="GET" action="{{ route('jobs.history.index', $job) }}">
                            <div class="row">
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label for="category">Category</label>
                                        <select name="category" id="category" class="form-control">
                                            <option value="">All Categories</option>
                                            @foreach($categories as $category)
                                                <option value="{{ $category }}" {{ request('category') === $category ? 'selected' : '' }}>
                                                    {{ ucfirst(str_replace('_', ' ', $category)) }}
                                                </option>
                                            @endforeach
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label for="type">Activity Type</label>
                                        <select name="type" id="type" class="form-control">
                                            <option value="">All Types</option>
                                            @foreach($types as $type)
                                                <option value="{{ $type }}" {{ request('type') === $type ? 'selected' : '' }}>
                                                    {{ ucfirst(str_replace('_', ' ', $type)) }}
                                                </option>
                                            @endforeach
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label for="user_id">User</label>
                                        <select name="user_id" id="user_id" class="form-control">
                                            <option value="">All Users</option>
                                            @foreach($users as $user)
                                                <option value="{{ $user->id }}" {{ request('user_id') == $user->id ? 'selected' : '' }}>
                                                    {{ $user->name }}
                                                </option>
                                            @endforeach
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label for="date_from">From Date</label>
                                        <input type="date" name="date_from" id="date_from" class="form-control" value="{{ request('date_from') }}">
                                    </div>
                                </div>
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label for="date_to">To Date</label>
                                        <input type="date" name="date_to" id="date_to" class="form-control" value="{{ request('date_to') }}">
                                    </div>
                                </div>
                                <div class="col-md-2">
                                    <div class="form-group">
                                        <label>&nbsp;</label>
                                        <div>
                                            <div class="form-check">
                                                <input type="checkbox" name="major_only" id="major_only" class="form-check-input" value="1" {{ request('major_only') ? 'checked' : '' }}>
                                                <label class="form-check-label" for="major_only">
                                                    Major activities only
                                                </label>
                                            </div>
                                            <button type="submit" class="btn btn-primary btn-sm mt-2">
                                                <i class="fas fa-search"></i> Filter
                                            </button>
                                            <a href="{{ route('jobs.history.index', $job) }}" class="btn btn-secondary btn-sm mt-2">
                                                <i class="fas fa-times"></i> Clear
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Activity Timeline -->
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-timeline"></i> Activity Timeline
                        <span class="badge badge-secondary">{{ $activities->total() }} activities</span>
                    </h5>
                </div>
                <div class="card-body">
                    @if($activities->count() > 0)
                        <div class="timeline">
                            @foreach($activities as $activity)
                                <div class="timeline-item {{ $activity->is_major_activity ? 'timeline-item-major' : '' }}">
                                    <div class="timeline-marker">
                                        <i class="{{ $activity->activity_icon }}"></i>
                                    </div>
                                    <div class="timeline-content">
                                        <div class="timeline-header">
                                            <h6 class="timeline-title">
                                                {{ ucfirst(str_replace('_', ' ', $activity->activity_type)) }}
                                                @if($activity->is_major_activity)
                                                    <i class="fas fa-star text-warning" title="Major Activity"></i>
                                                @endif
                                                <span class="badge {{ $activity->priority_badge }} badge-sm">
                                                    {{ ucfirst($activity->priority_level) }}
                                                </span>
                                            </h6>
                                            <div class="timeline-meta">
                                                <span class="text-muted">
                                                    <i class="fas fa-clock"></i>
                                                    {{ $activity->created_at->format('M d, Y H:i:s') }}
                                                    ({{ $activity->created_at->diffForHumans() }})
                                                </span>
                                                <span class="text-muted ml-3">
                                                    <i class="fas fa-user"></i>
                                                    {{ $activity->user->name ?? 'System' }}
                                                    @if($activity->user_role)
                                                        ({{ $activity->user_role }})
                                                    @endif
                                                </span>
                                                @if($activity->affected_user_id)
                                                    <span class="text-muted ml-3">
                                                        <i class="fas fa-arrow-right"></i>
                                                        {{ $activity->affectedUser->name ?? 'Unknown' }}
                                                    </span>
                                                @endif
                                            </div>
                                        </div>
                                        <div class="timeline-body">
                                            <p class="mb-2">{{ $activity->description }}</p>

                                            @if($activity->old_values && !empty($activity->old_values))
                                                <div class="activity-values">
                                                    <strong>Previous values:</strong>
                                                    <div class="badge-container">
                                                        @foreach($activity->old_values as $key => $value)
                                                            <span class="badge badge-light">
                                                                {{ ucfirst(str_replace('_', ' ', $key)) }}: {{ is_array($value) ? implode(', ', $value) : $value }}
                                                            </span>
                                                        @endforeach
                                                    </div>
                                                </div>
                                            @endif

                                            @if($activity->new_values && !empty($activity->new_values))
                                                <div class="activity-values mt-2">
                                                    <strong>New values:</strong>
                                                    <div class="badge-container">
                                                        @foreach($activity->new_values as $key => $value)
                                                            <span class="badge badge-success">
                                                                {{ ucfirst(str_replace('_', ' ', $key)) }}: {{ is_array($value) ? implode(', ', $value) : $value }}
                                                            </span>
                                                        @endforeach
                                                    </div>
                                                </div>
                                            @endif

                                            @if($activity->related_entity_name)
                                                <div class="mt-2">
                                                    <small class="text-info">
                                                        <i class="fas fa-link"></i>
                                                        Related: {{ $activity->related_entity_name }}
                                                    </small>
                                                </div>
                                            @endif
                                        </div>
                                        <div class="timeline-footer">
                                            <a href="{{ route('jobs.history.show', [$job, $activity]) }}" class="btn btn-sm btn-outline-primary">
                                                <i class="fas fa-eye"></i> View Details
                                            </a>
                                            <span class="badge badge-outline-{{ $activity->activity_category === 'job' ? 'primary' : ($activity->activity_category === 'task' ? 'success' : 'info') }}">
                                                {{ ucfirst($activity->activity_category) }}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            @endforeach
                        </div>

                        <!-- Pagination -->
                        <div class="d-flex justify-content-center mt-4">
                            {{ $activities->appends(request()->query())->links() }}
                        </div>
                    @else
                        <div class="text-center py-5">
                            <i class="fas fa-history fa-3x text-muted mb-3"></i>
                            <h5 class="text-muted">No activities found</h5>
                            <p class="text-muted">Try adjusting your filters to see more activities.</p>
                        </div>
                    @endif
                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@push('styles')
<style>
.timeline-content {
    background: #fff;
    border: 1px solid #e9ecef;
    border-radius: 8px;
    padding: 20px;
    margin-left: 15px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.timeline-header {
    border-bottom: 1px solid #e9ecef;
    padding-bottom: 10px;
    margin-bottom: 15px;
}

.timeline-title {
    margin: 0;
    color: #495057;
}

.timeline-meta {
    margin-top: 5px;
}

.timeline-meta span {
    margin-right: 15px;
}

.timeline-body {
    margin-bottom: 15px;
}

.timeline-footer {
    padding-top: 10px;
    border-top: 1px solid #e9ecef;
    display: flex;
    justify-content: between;
    align-items: center;
}

.activity-values {
    margin: 10px 0;
}

.badge-container {
    margin-top: 5px;
}

.badge-container .badge {
    margin-right: 5px;
    margin-bottom: 3px;
}

.stat-item h4 {
    margin-bottom: 5px;
}

.badge-outline-primary {
    color: #007bff;
    border: 1px solid #007bff;
    background: transparent;
}

.badge-outline-success {
    color: #28a745;
    border: 1px solid #28a745;
    background: transparent;
}

.badge-outline-info {
    color: #17a2b8;
    border: 1px solid #17a2b8;
    background: transparent;
}

@media (max-width: 768px) {
    .timeline {
        padding-left: 20px;
    }

    .timeline:before {
        left: 10px;
    }

    .timeline-marker {
        left: -17px;
        width: 25px;
        height: 25px;
    }

    .timeline-content {
        margin-left: 10px;
    }

    .timeline-item-major {
        margin-left: -10px;
        padding: 10px;
    }
}
</style>
@endpush

@push('scripts')
<script>
$(document).ready(function() {
    // Auto-submit form when filter values change
    $('#category, #type, #user_id').on('change', function() {
        $(this).closest('form').submit();
    });

    // Auto-submit when major_only checkbox is changed
    $('#major_only').on('change', function() {
        $(this).closest('form').submit();
    });

    // Smooth scroll to timeline when filters applied
    @if(request()->hasAny(['category', 'type', 'user_id', 'date_from', 'date_to', 'major_only']))
        setTimeout(function() {
            $('html, body').animate({
                scrollTop: $('.timeline').offset().top - 100
            }, 500);
        }, 100);
    @endif
});
</script>
@endpush
