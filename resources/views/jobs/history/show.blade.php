{{-- resources/views/jobs/history/show.blade.php --}}
@extends('layouts.app')

@section('title', 'Activity Details - Job #' . $job->id)

@section('content')
<div class="container-fluid">
    <!-- Header Navigation -->
    <div class="row mb-4">
        <div class="col-12">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="{{ route('jobs.index') }}">Jobs</a>
                    </li>
                    <li class="breadcrumb-item">
                        <a href="{{ route('jobs.show', $job) }}">Job #{{ $job->id }}</a>
                    </li>
                    <li class="breadcrumb-item">
                        <a href="{{ route('jobs.history.index', $job) }}">History</a>
                    </li>
                    <li class="breadcrumb-item active" aria-current="page">Activity Details</li>
                </ol>
            </nav>
        </div>
    </div>

    <!-- Page Header -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <h4 class="mb-0">
                            <i class="fas fa-info-circle text-primary"></i>
                            Activity Details
                        </h4>
                        <small class="text-muted">
                            {{ ucfirst(str_replace('_', ' ', $activity->activity_type)) }} -
                            {{ $activity->created_at->format('M d, Y H:i:s') }}
                        </small>
                    </div>
                    <div class="btn-group">
                        <a href="{{ route('jobs.history.index', $job) }}" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left"></i> Back to History
                        </a>
                        <a href="{{ route('jobs.show', $job) }}" class="btn btn-outline-primary">
                            <i class="fas fa-eye"></i> View Job
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <!-- Main Activity Details -->
        <div class="col-lg-8">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="{{ $activity->activity_icon }}"></i>
                        {{ ucfirst(str_replace('_', ' ', $activity->activity_type)) }}
                        @if($activity->is_major_activity)
                            <i class="fas fa-star text-warning ml-2" title="Major Activity"></i>
                        @endif
                        <span class="badge {{ $activity->priority_badge }} ml-2">
                            {{ ucfirst($activity->priority_level) }} Priority
                        </span>
                    </h5>
                </div>
                <div class="card-body">
                    <!-- Activity Description -->
                    <div class="activity-description mb-4">
                        <h6><i class="fas fa-align-left text-primary"></i> Description</h6>
                        <p class="lead">{{ $activity->description }}</p>
                    </div>

                    <!-- Activity Details Table -->
                    <div class="row">
                        <div class="col-md-6">
                            <h6><i class="fas fa-info text-info"></i> Basic Information</h6>
                            <table class="table table-sm table-bordered">
                                <tr>
                                    <th width="40%">Activity Type</th>
                                    <td>{{ ucfirst(str_replace('_', ' ', $activity->activity_type)) }}</td>
                                </tr>
                                <tr>
                                    <th>Category</th>
                                    <td>
                                        <span class="badge badge-outline-{{
                                            $activity->activity_category === 'job' ? 'primary' :
                                            ($activity->activity_category === 'task' ? 'success' :
                                            ($activity->activity_category === 'item' ? 'info' :
                                            ($activity->activity_category === 'approval' ? 'warning' : 'secondary')))
                                        }}">
                                            {{ ucfirst($activity->activity_category) }}
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Priority Level</th>
                                    <td>
                                        <span class="badge {{ $activity->priority_badge }}">
                                            {{ ucfirst($activity->priority_level) }}
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Major Activity</th>
                                    <td>
                                        @if($activity->is_major_activity)
                                            <span class="badge badge-warning">
                                                <i class="fas fa-star"></i> Yes
                                            </span>
                                        @else
                                            <span class="badge badge-secondary">No</span>
                                        @endif
                                    </td>
                                </tr>
                                <tr>
                                    <th>Date & Time</th>
                                    <td>
                                        {{ $activity->created_at->format('M d, Y H:i:s') }}
                                        <br>
                                        <small class="text-muted">
                                            ({{ $activity->created_at->diffForHumans() }})
                                        </small>
                                    </td>
                                </tr>
                            </table>
                        </div>

                        <div class="col-md-6">
                            <h6><i class="fas fa-users text-success"></i> User Information</h6>
                            <table class="table table-sm table-bordered">
                                <tr>
                                    <th width="40%">Performed By</th>
                                    <td>
                                        @if($activity->user)
                                            <div class="d-flex align-items-center">
                                                <div class="avatar-sm bg-primary text-white rounded-circle d-flex align-items-center justify-content-center mr-2">
                                                    {{ substr($activity->user->name, 0, 1) }}
                                                </div>
                                                <div>
                                                    <strong>{{ $activity->user->name }}</strong>
                                                    @if($activity->user_role)
                                                        <br><small class="text-muted">{{ $activity->user_role }}</small>
                                                    @endif
                                                </div>
                                            </div>
                                        @else
                                            <span class="text-muted">System</span>
                                        @endif
                                    </td>
                                </tr>
                                @if($activity->affected_user_id)
                                <tr>
                                    <th>Affected User</th>
                                    <td>
                                        @if($activity->affectedUser)
                                            <div class="d-flex align-items-center">
                                                <div class="avatar-sm bg-info text-white rounded-circle d-flex align-items-center justify-content-center mr-2">
                                                    {{ substr($activity->affectedUser->name, 0, 1) }}
                                                </div>
                                                <strong>{{ $activity->affectedUser->name }}</strong>
                                            </div>
                                        @else
                                            <span class="text-muted">Unknown User</span>
                                        @endif
                                    </td>
                                </tr>
                                @endif
                                <tr>
                                    <th>IP Address</th>
                                    <td>
                                        <code>{{ $activity->ip_address ?: 'N/A' }}</code>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Browser</th>
                                    <td>{{ $activity->browser_info ?: 'N/A' }}</td>
                                </tr>
                            </table>
                        </div>
                    </div>

                    <!-- Previous Values -->
                    @if($activity->old_values && !empty($activity->old_values))
                    <div class="mt-4">
                        <h6><i class="fas fa-history text-warning"></i> Previous Values</h6>
                        <div class="card bg-light">
                            <div class="card-body">
                                <div class="row">
                                    @foreach($activity->old_values as $key => $value)
                                    <div class="col-md-6 mb-2">
                                        <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                                        <div class="value-display">
                                            @if(is_array($value))
                                                @foreach($value as $item)
                                                    <span class="badge badge-light">{{ $item }}</span>
                                                @endforeach
                                            @else
                                                <span class="text-muted">{{ $value ?: 'N/A' }}</span>
                                            @endif
                                        </div>
                                    </div>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                    </div>
                    @endif

                    <!-- New Values -->
                    @if($activity->new_values && !empty($activity->new_values))
                    <div class="mt-4">
                        <h6><i class="fas fa-plus-circle text-success"></i> New Values</h6>
                        <div class="card bg-light">
                            <div class="card-body">
                                <div class="row">
                                    @foreach($activity->new_values as $key => $value)
                                    <div class="col-md-6 mb-2">
                                        <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                                        <div class="value-display">
                                            @if(is_array($value))
                                                @foreach($value as $item)
                                                    <span class="badge badge-success">{{ $item }}</span>
                                                @endforeach
                                            @else
                                                <span class="text-success">{{ $value ?: 'N/A' }}</span>
                                            @endif
                                        </div>
                                    </div>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                    </div>
                    @endif

                    <!-- Metadata -->
                    @if($activity->metadata && !empty($activity->metadata))
                    <div class="mt-4">
                        <h6><i class="fas fa-database text-info"></i> Additional Information</h6>
                        <div class="card bg-light">
                            <div class="card-body">
                                <div class="row">
                                    @foreach($activity->metadata as $key => $value)
                                    <div class="col-md-6 mb-2">
                                        <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                                        <div class="value-display">
                                            @if(is_array($value))
                                                @foreach($value as $item)
                                                    <span class="badge badge-info">{{ $item }}</span>
                                                @endforeach
                                            @else
                                                <span class="text-info">{{ $value ?: 'N/A' }}</span>
                                            @endif
                                        </div>
                                    </div>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                    </div>
                    @endif
                </div>
            </div>
        </div>

        <!-- Sidebar Information -->
        <div class="col-lg-4">
            <!-- Job Information -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-briefcase text-primary"></i>
                        Related Job
                    </h5>
                </div>
                <div class="card-body">
                    <div class="job-info-item mb-3">
                        <strong>Job #{{ $job->id }}</strong>
                        <p class="text-muted mb-0">{{ $job->description }}</p>
                    </div>

                    <div class="job-details">
                        <div class="row text-center">
                            <div class="col-6">
                                <div class="info-stat">
                                    <span class="badge badge-{{ $job->status === 'completed' ? 'success' : ($job->status === 'cancelled' ? 'danger' : 'warning') }}">
                                        {{ ucfirst($job->status) }}
                                    </span>
                                    <div class="info-label">Status</div>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="info-stat">
                                    <span class="badge badge-{{ $job->priority == 1 ? 'danger' : ($job->priority == 2 ? 'warning' : 'info') }}">
                                        Priority {{ $job->priority }}
                                    </span>
                                    <div class="info-label">Priority</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <hr>

                    <div class="job-meta">
                        @if($job->jobType)
                        <p><strong>Type:</strong> {{ $job->jobType->name }}</p>
                        @endif
                        @if($job->client)
                        <p><strong>Client:</strong> {{ $job->client->name }}</p>
                        @endif
                        @if($job->equipment)
                        <p><strong>Equipment:</strong> {{ $job->equipment->name }}</p>
                        @endif
                        <p><strong>Created:</strong> {{ $job->created_at->format('M d, Y') }}</p>
                    </div>

                    <div class="mt-3">
                        <a href="{{ route('jobs.show', $job) }}" class="btn btn-primary btn-sm btn-block">
                            <i class="fas fa-eye"></i> View Full Job
                        </a>
                    </div>
                </div>
            </div>

            <!-- Related Entity Information -->
            @if($activity->related_model_type && $activity->related_entity_name)
            <div class="card mt-3">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-link text-info"></i>
                        Related Entity
                    </h5>
                </div>
                <div class="card-body">
                    <div class="related-entity-info">
                        <p><strong>Type:</strong> {{ $activity->related_model_type }}</p>
                        <p><strong>Name:</strong> {{ $activity->related_entity_name }}</p>
                        @if($activity->related_model_id)
                        <p><strong>ID:</strong> #{{ $activity->related_model_id }}</p>
                        @endif
                    </div>
                </div>
            </div>
            @endif

            <!-- Activity Navigation -->
            <div class="card mt-3">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-navigation text-secondary"></i>
                        Navigation
                    </h5>
                </div>
                <div class="card-body">
                    <div class="navigation-buttons d-grid gap-2">
                        <a href="{{ route('jobs.history.index', $job) }}" class="btn btn-outline-secondary btn-sm">
                            <i class="fas fa-list"></i> All Activities
                        </a>
                        <a href="{{ route('jobs.history.index', $job) }}?major_only=1" class="btn btn-outline-warning btn-sm">
                            <i class="fas fa-star"></i> Major Activities Only
                        </a>
                        <a href="{{ route('jobs.history.index', $job) }}?category={{ $activity->activity_category }}" class="btn btn-outline-info btn-sm">
                            <i class="fas fa-filter"></i> Same Category
                        </a>
                        @if($activity->user_id)
                        <a href="{{ route('jobs.history.index', $job) }}?user_id={{ $activity->user_id }}" class="btn btn-outline-success btn-sm">
                            <i class="fas fa-user"></i> Same User
                        </a>
                        @endif
                    </div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="card mt-3">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="fas fa-tools text-primary"></i>
                        Quick Actions
                    </h5>
                </div>
                <div class="card-body">
                    <div class="d-grid gap-2">
                        <a href="{{ route('jobs.history.export.pdf', $job) }}?activity_id={{ $activity->id }}" class="btn btn-danger btn-sm">
                            <i class="fas fa-file-pdf"></i> Export as PDF
                        </a>
                        <a href="{{ route('jobs.history.export.word', $job) }}?activity_id={{ $activity->id }}" class="btn btn-primary btn-sm">
                            <i class="fas fa-file-word"></i> Export as Word
                        </a>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="window.print()">
                            <i class="fas fa-print"></i> Print Details
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@push('styles')
<style>
.avatar-sm {
    width: 32px;
    height: 32px;
    font-size: 14px;
    font-weight: bold;
}

.activity-description {
    padding: 15px;
    background: #f8f9fa;
    border-left: 4px solid #007bff;
    border-radius: 4px;
}

.value-display {
    margin-top: 5px;
}

.value-display .badge {
    margin-right: 5px;
    margin-bottom: 3px;
}

.info-stat {
    text-align: center;
}

.info-label {
    font-size: 11px;
    color: #666;
    margin-top: 5px;
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

.badge-outline-warning {
    color: #ffc107;
    border: 1px solid #ffc107;
    background: transparent;
}

.badge-outline-secondary {
    color: #6c757d;
    border: 1px solid #6c757d;
    background: transparent;
}

.job-info-item {
    border-bottom: 1px solid #e9ecef;
    padding-bottom: 10px;
}

.related-entity-info p {
    margin-bottom: 8px;
}

.navigation-buttons .btn {
    margin-bottom: 8px;
}

@media print {
    .btn, .card-header {
        display: none !important;
    }

    .card {
        border: none !important;
        box-shadow: none !important;
    }

    .col-lg-4 {
        display: none !important;
    }

    .col-lg-8 {
        width: 100% !important;
        max-width: 100% !important;
    }
}

@media (max-width: 768px) {
    .navigation-buttons {
        margin-bottom: 10px;
    }

    .job-details .row {
        margin-bottom: 15px;
    }

    .value-display .badge {
        font-size: 10px;
        padding: 2px 6px;
    }
}
</style>
@endpush

@push('scripts')
<script>
$(document).ready(function() {
    // Add smooth animations to value displays
    $('.value-display .badge').each(function(index) {
        $(this).delay(index * 100).fadeIn(500);
    });

    // Add tooltips to badges
    $('.badge').tooltip({
        placement: 'top',
        trigger: 'hover'
    });

    // Add confirmation for export actions
    $('a[href*="export"]').on('click', function(e) {
        const format = $(this).text().includes('PDF') ? 'PDF' : 'Word';
        if (!confirm(`Export this activity details as ${format}?`)) {
            e.preventDefault();
        }
    });
});
</script>
@endpush
