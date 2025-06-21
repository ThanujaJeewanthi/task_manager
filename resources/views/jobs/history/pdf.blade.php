{{-- resources/views/jobs/history/pdf.blade.php --}}
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Job History Report - Job #{{ $job->id }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            font-size: 12px;
            line-height: 1.4;
            color: #333;
            margin: 0;
            padding: 20px;
        }

        .header {
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #007bff;
            font-size: 24px;
            margin: 0;
        }

        .header .subtitle {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }

        .job-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .job-info h2 {
            color: #495057;
            font-size: 16px;
            margin: 0 0 15px 0;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 5px;
        }

        .info-grid {
            display: table;
            width: 100%;
        }

        .info-row {
            display: table-row;
        }

        .info-label, .info-value {
            display: table-cell;
            padding: 5px 10px 5px 0;
            vertical-align: top;
        }

        .info-label {
            font-weight: bold;
            width: 25%;
        }

        .stats-section {
            margin-bottom: 25px;
        }

        .stats-grid {
            display: table;
            width: 100%;
            border-collapse: collapse;
        }

        .stats-row {
            display: table-row;
        }

        .stats-cell {
            display: table-cell;
            padding: 10px;
            text-align: center;
            border: 1px solid #dee2e6;
            background: #f8f9fa;
        }

        .stats-number {
            font-size: 18px;
            font-weight: bold;
            color: #007bff;
        }

        .stats-label {
            color: #666;
            font-size: 11px;
        }

        .activities-section h2 {
            color: #495057;
            font-size: 18px;
            margin: 30px 0 20px 0;
            border-bottom: 2px solid #007bff;
            padding-bottom: 5px;
        }

        .activity-item {
            border: 1px solid #dee2e6;
            border-radius: 5px;
            margin-bottom: 15px;
            padding: 15px;
            page-break-inside: avoid;
        }

        .activity-item.major {
            border-left: 4px solid #ffc107;
            background: #fff9e6;
        }

        .activity-header {
            margin-bottom: 10px;
        }

        .activity-title {
            font-size: 14px;
            font-weight: bold;
            color: #495057;
            margin: 0;
        }

        .activity-meta {
            color: #666;
            font-size: 11px;
            margin-top: 5px;
        }

        .activity-description {
            margin: 10px 0;
            line-height: 1.5;
        }

        .activity-values {
            margin: 10px 0;
        }

        .activity-values-title {
            font-weight: bold;
            color: #495057;
            font-size: 11px;
        }

        .values-list {
            margin: 5px 0;
            padding: 5px;
            background: #f8f9fa;
            border-radius: 3px;
            font-size: 11px;
        }

        .badge {
            display: inline-block;
            padding: 2px 6px;
            font-size: 10px;
            font-weight: bold;
            border-radius: 3px;
            margin-right: 5px;
        }

        .badge-warning {
            background: #ffc107;
            color: #212529;
        }

        .badge-success {
            background: #28a745;
            color: white;
        }

        .badge-danger {
            background: #dc3545;
            color: white;
        }

        .badge-primary {
            background: #007bff;
            color: white;
        }

        .badge-secondary {
            background: #6c757d;
            color: white;
        }

        .badge-info {
            background: #17a2b8;
            color: white;
        }

        .footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #666;
            font-size: 10px;
        }

        .page-break {
            page-break-before: always;
        }

        @media print {
            body {
                margin: 0;
                padding: 15px;
            }

            .activity-item {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <h1>Job Activity History Report</h1>
        <div class="subtitle">Job #{{ $job->id }} - {{ $job->description }}</div>
        <div class="subtitle">Generated on {{ $generated_at->format('M d, Y H:i:s') }} by {{ $generated_by->name }}</div>
    </div>

    <!-- Job Information -->
    <div class="job-info">
        <h2>Job Information</h2>
        <div class="info-grid">
            <div class="info-row">
                <div class="info-label">Job ID:</div>
                <div class="info-value">#{{ $job->id }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Description:</div>
                <div class="info-value">{{ $job->description ?: 'N/A' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Job Type:</div>
                <div class="info-value">{{ $job->jobType->name ?? 'N/A' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Client:</div>
                <div class="info-value">{{ $job->client->name ?? 'N/A' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Equipment:</div>
                <div class="info-value">{{ $job->equipment->name ?? 'N/A' }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Status:</div>
                <div class="info-value">
                    <span class="badge badge-{{ $job->status === 'completed' ? 'success' : ($job->status === 'cancelled' ? 'danger' : 'warning') }}">
                        {{ ucfirst($job->status) }}
                    </span>
                </div>
            </div>
            <div class="info-row">
                <div class="info-label">Priority:</div>
                <div class="info-value">
                    <span class="badge badge-{{ $job->priority == 1 ? 'danger' : ($job->priority == 2 ? 'warning' : 'info') }}">
                        Priority {{ $job->priority }}
                    </span>
                </div>
            </div>
            <div class="info-row">
                <div class="info-label">Created:</div>
                <div class="info-value">{{ $job->created_at->format('M d, Y H:i:s') }}</div>
            </div>
            @if($job->completed_date)
            <div class="info-row">
                <div class="info-label">Completed:</div>
                <div class="info-value">{{ $job->completed_date->format('M d, Y H:i:s') }}</div>
            </div>
            @endif
        </div>
    </div>

    <!-- Activity Statistics -->
    <div class="stats-section">
        <h2>Activity Summary</h2>
        <div class="stats-grid">
            <div class="stats-row">
                <div class="stats-cell">
                    <div class="stats-number">{{ $stats['total_activities'] }}</div>
                    <div class="stats-label">Total Activities</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-number">{{ $stats['major_activities'] }}</div>
                    <div class="stats-label">Major Activities</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-number">{{ $stats['users_involved'] }}</div>
                    <div class="stats-label">Users Involved</div>
                </div>
                <div class="stats-cell">
                    <div class="stats-number">{{ $activities->count() }}</div>
                    <div class="stats-label">Activities in Report</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Applied Filters -->
    @if(!empty(array_filter($filters)))
    <div class="job-info">
        <h2>Applied Filters</h2>
        <div class="info-grid">
            @if(!empty($filters['category']))
            <div class="info-row">
                <div class="info-label">Category:</div>
                <div class="info-value">{{ ucfirst(str_replace('_', ' ', $filters['category'])) }}</div>
            </div>
            @endif
            @if(!empty($filters['type']))
            <div class="info-row">
                <div class="info-label">Activity Type:</div>
                <div class="info-value">{{ ucfirst(str_replace('_', ' ', $filters['type'])) }}</div>
            </div>
            @endif
            @if(!empty($filters['user_id']))
            <div class="info-row">
                <div class="info-label">User Filter:</div>
                <div class="info-value">Applied</div>
            </div>
            @endif
            @if(!empty($filters['date_from']) && !empty($filters['date_to']))
            <div class="info-row">
                <div class="info-label">Date Range:</div>
                <div class="info-value">{{ $filters['date_from'] }} to {{ $filters['date_to'] }}</div>
            </div>
            @endif
            @if(!empty($filters['major_only']))
            <div class="info-row">
                <div class="info-label">Show Only:</div>
                <div class="info-value">Major Activities</div>
            </div>
            @endif
        </div>
    </div>
    @endif

    <!-- Activities Timeline -->
    <div class="activities-section">
        <h2>Activity Timeline</h2>

        @forelse($activities as $index => $activity)
            @if($index > 0 && $index % 10 === 0)
                <div class="page-break"></div>
            @endif

            <div class="activity-item {{ $activity->is_major_activity ? 'major' : '' }}">
                <div class="activity-header">
                    <h3 class="activity-title">
                        {{ ucfirst(str_replace('_', ' ', $activity->activity_type)) }}
                        @if($activity->is_major_activity)
                            ★
                        @endif
                        <span class="badge badge-{{
                            $activity->priority_level === 'critical' ? 'danger' :
                            ($activity->priority_level === 'high' ? 'warning' :
                            ($activity->priority_level === 'medium' ? 'primary' : 'secondary'))
                        }}">
                            {{ ucfirst($activity->priority_level) }}
                        </span>
                    </h3>
                    <div class="activity-meta">
                        <strong>Date:</strong> {{ $activity->created_at->format('M d, Y H:i:s') }} |
                        <strong>User:</strong> {{ $activity->user->name ?? 'System' }}
                        @if($activity->user_role)
                            ({{ $activity->user_role }})
                        @endif
                        @if($activity->affected_user_id)
                            | <strong>Affected:</strong> {{ $activity->affectedUser->name ?? 'Unknown' }}
                        @endif
                        | <strong>Category:</strong> {{ ucfirst($activity->activity_category) }}
                    </div>
                </div>

                <div class="activity-description">
                    {{ $activity->description }}
                </div>

                @if($activity->old_values && !empty($activity->old_values))
                <div class="activity-values">
                    <div class="activity-values-title">Previous Values:</div>
                    <div class="values-list">
                        @foreach($activity->old_values as $key => $value)
                            <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                            {{ is_array($value) ? implode(', ', $value) : $value }}
                            @if(!$loop->last) | @endif
                        @endforeach
                    </div>
                </div>
                @endif

                @if($activity->new_values && !empty($activity->new_values))
                <div class="activity-values">
                    <div class="activity-values-title">New Values:</div>
                    <div class="values-list">
                        @foreach($activity->new_values as $key => $value)
                            <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                            {{ is_array($value) ? implode(', ', $value) : $value }}
                            @if(!$loop->last) | @endif
                        @endforeach
                    </div>
                </div>
                @endif

                @if($activity->metadata && !empty($activity->metadata))
                <div class="activity-values">
                    <div class="activity-values-title">Additional Information:</div>
                    <div class="values-list">
                        @foreach($activity->metadata as $key => $value)
                            @if($key !== 'notes' && $key !== 'approval_notes' && $key !== 'review_notes')
                                <strong>{{ ucfirst(str_replace('_', ' ', $key)) }}:</strong>
                                {{ is_array($value) ? implode(', ', $value) : $value }}
                                @if(!$loop->last) | @endif
                            @endif
                        @endforeach
                    </div>
                </div>
                @endif

                @if($activity->related_entity_name)
                <div class="activity-values">
                    <div class="activity-values-title">Related Entity:</div>
                    <div class="values-list">{{ $activity->related_entity_name }}</div>
                </div>
                @endif
            </div>
        @empty
            <div style="text-align: center; padding: 40px; color: #666;">
                <div style="font-size: 48px; margin-bottom: 20px;">📋</div>
                <h3>No Activities Found</h3>
                <p>No activities match the selected criteria.</p>
            </div>
        @endforelse
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>
            This report was generated on {{ $generated_at->format('M d, Y \a\t H:i:s') }} by {{ $generated_by->name }}.
            <br>
            Report contains {{ $activities->count() }} activities from Job #{{ $job->id }}.
        </p>
    </div>
</body>
</html>
