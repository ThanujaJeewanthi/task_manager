<?php

namespace App\Http\Controllers\Job;

use App\Http\Controllers\Controller;
use App\Models\Job;
use App\Models\JobActivityLog;
use App\Services\JobActivityLogger;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Barryvdh\DomPDF\Facade\Pdf;
use PhpOffice\PhpWord\PhpWord;
use PhpOffice\PhpWord\IOFactory;
use PhpOffice\PhpWord\Style\Font;
use Carbon\Carbon;

class JobHistoryController extends Controller
{
    /**
     * Display job history timeline.
     */
    public function index(Job $job, Request $request)
    {
        // Check company access
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        // Get filter parameters
        $filters = $request->only(['category', 'type', 'user_id', 'date_from', 'date_to', 'major_only']);

        // Build query
        $query = JobActivityLog::where('job_id', $job->id)
            ->with(['user', 'affectedUser'])
            ->orderBy('created_at', 'desc');

        // Apply filters
        if (!empty($filters['category'])) {
            $query->byCategory($filters['category']);
        }

        if (!empty($filters['type'])) {
            $query->byType($filters['type']);
        }

        if (!empty($filters['user_id'])) {
            $query->byUser($filters['user_id']);
        }

        if (!empty($filters['date_from']) && !empty($filters['date_to'])) {
            $query->inDateRange($filters['date_from'], $filters['date_to']);
        }

        if (!empty($filters['major_only'])) {
            $query->majorActivities();
        }

        $activities = $query->paginate(20)->appends($request->query());

        // Get activity statistics
        $stats = JobActivityLogger::getJobActivityStats($job->id);

        // Get unique users for filter dropdown
        $users = JobActivityLog::where('job_id', $job->id)
            ->with('user')
            ->select('user_id')
            ->distinct()
            ->get()
            ->pluck('user')
            ->filter()
            ->unique('id');

        // Get available categories and types for filters
        $categories = JobActivityLog::where('job_id', $job->id)
            ->distinct('activity_category')
            ->pluck('activity_category');

        $types = JobActivityLog::where('job_id', $job->id)
            ->distinct('activity_type')
            ->pluck('activity_type');

        return view('jobs.history.index', compact(
            'job', 'activities', 'stats', 'users', 'categories', 'types', 'filters'
        ));
    }

    /**
     * Show detailed activity information.
     */
    public function show(Job $job, JobActivityLog $activity)
    {
        // Check company access
        if ($job->company_id !== Auth::user()->company_id || $activity->job_id !== $job->id) {
            abort(403);
        }

        $activity->load(['user', 'affectedUser', 'job']);

        return view('jobs.history.show', compact('job', 'activity'));
    }

    /**
     * Export job history as PDF.
     */
    public function exportPdf(Job $job, Request $request)
    {
        // Check company access
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $filters = $request->only(['category', 'type', 'user_id', 'date_from', 'date_to', 'major_only']);

        // Get activities based on filters
        $query = JobActivityLog::where('job_id', $job->id)
            ->with(['user', 'affectedUser', 'job.jobType', 'job.client', 'job.equipment'])
            ->orderBy('created_at', 'desc');

        // Apply filters
        if (!empty($filters['category'])) {
            $query->byCategory($filters['category']);
        }

        if (!empty($filters['type'])) {
            $query->byType($filters['type']);
        }

        if (!empty($filters['user_id'])) {
            $query->byUser($filters['user_id']);
        }

        if (!empty($filters['date_from']) && !empty($filters['date_to'])) {
            $query->inDateRange($filters['date_from'], $filters['date_to']);
        }

        if (!empty($filters['major_only'])) {
            $query->majorActivities();
        }

        $activities = $query->get();
        $stats = JobActivityLogger::getJobActivityStats($job->id);

        $data = [
            'job' => $job,
            'activities' => $activities,
            'stats' => $stats,
            'filters' => $filters,
            'generated_at' => now(),
            'generated_by' => Auth::user(),
        ];

        $pdf = Pdf::loadView('jobs.history.pdf', $data);

        $filename = "job-{$job->id}-history-" . now()->format('Y-m-d-H-i-s') . ".pdf";

        return $pdf->download($filename);
    }

    /**
     * Export job history as Word document.
     */
    public function exportWord(Job $job, Request $request)
    {
        // Check company access
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $filters = $request->only(['category', 'type', 'user_id', 'date_from', 'date_to', 'major_only']);

        // Get activities based on filters
        $query = JobActivityLog::where('job_id', $job->id)
            ->with(['user', 'affectedUser', 'job.jobType', 'job.client', 'job.equipment'])
            ->orderBy('created_at', 'desc');

        // Apply filters (same as PDF)
        if (!empty($filters['category'])) {
            $query->byCategory($filters['category']);
        }

        if (!empty($filters['type'])) {
            $query->byType($filters['type']);
        }

        if (!empty($filters['user_id'])) {
            $query->byUser($filters['user_id']);
        }

        if (!empty($filters['date_from']) && !empty($filters['date_to'])) {
            $query->inDateRange($filters['date_from'], $filters['date_to']);
        }

        if (!empty($filters['major_only'])) {
            $query->majorActivities();
        }

        $activities = $query->get();
        $stats = JobActivityLogger::getJobActivityStats($job->id);

        // Create Word document
        $phpWord = new PhpWord();

        // Document properties
        $properties = $phpWord->getDocInfo();
        $properties->setCreator(Auth::user()->name);
        $properties->setCompany($job->company->name ?? 'Company');
        $properties->setTitle("Job History Report - Job #{$job->id}");
        $properties->setDescription("Complete activity history for job #{$job->id}");

        // Add section
        $section = $phpWord->addSection([
            'marginTop' => 1440,
            'marginBottom' => 1440,
            'marginLeft' => 1440,
            'marginRight' => 1440,
        ]);

        // Title styles
        $phpWord->addTitleStyle(1, ['size' => 16, 'bold' => true, 'color' => '1f4e79']);
        $phpWord->addTitleStyle(2, ['size' => 14, 'bold' => true, 'color' => '2e75b6']);
        $phpWord->addTitleStyle(3, ['size' => 12, 'bold' => true, 'color' => '70ad47']);

        // Header
        $section->addTitle("Job History Report", 1);
        $section->addTextBreak(1);

        // Job Information
        $section->addTitle("Job Information", 2);
        $jobInfoTable = $section->addTable([
            'borderSize' => 6,
            'borderColor' => '999999',
            'cellMargin' => 80,
        ]);

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Job ID:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->id);

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Description:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->description ?: 'N/A');

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Job Type:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->jobType->name ?? 'N/A');

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Client:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->client->name ?? 'N/A');

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Equipment:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->equipment->name ?? 'N/A');

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Status:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText(ucfirst($job->status));

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Priority:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText("Priority {$job->priority}");

        $jobInfoTable->addRow();
        $jobInfoTable->addCell(3000)->addText('Created:', ['bold' => true]);
        $jobInfoTable->addCell(6000)->addText($job->created_at->format('M d, Y H:i:s'));

        $section->addTextBreak(2);

        // Activity Statistics
        $section->addTitle("Activity Summary", 2);
        $statsTable = $section->addTable([
            'borderSize' => 6,
            'borderColor' => '999999',
            'cellMargin' => 80,
        ]);

        $statsTable->addRow();
        $statsTable->addCell(3000)->addText('Total Activities:', ['bold' => true]);
        $statsTable->addCell(6000)->addText($stats['total_activities']);

        $statsTable->addRow();
        $statsTable->addCell(3000)->addText('Major Activities:', ['bold' => true]);
        $statsTable->addCell(6000)->addText($stats['major_activities']);

        $statsTable->addRow();
        $statsTable->addCell(3000)->addText('Users Involved:', ['bold' => true]);
        $statsTable->addCell(6000)->addText($stats['users_involved']);

        $statsTable->addRow();
        $statsTable->addCell(3000)->addText('Last Activity:', ['bold' => true]);
        $statsTable->addCell(6000)->addText($stats['last_activity'] ? $stats['last_activity']->format('M d, Y H:i:s') : 'N/A');

        $section->addTextBreak(2);

        // Activity Timeline
        $section->addTitle("Activity Timeline", 2);
        $section->addTextBreak(1);

        foreach ($activities as $activity) {
            // Activity header
            $activityTitle = $activity->is_major_activity ? "★ " : "";
            $activityTitle .= ucfirst(str_replace('_', ' ', $activity->activity_type));
            $activityTitle .= " - " . ucfirst($activity->activity_category);

            $section->addTitle($activityTitle, 3);

            // Activity details table
            $activityTable = $section->addTable([
                'borderSize' => 3,
                'borderColor' => 'cccccc',
                'cellMargin' => 60,
            ]);

            $activityTable->addRow();
            $activityTable->addCell(2500)->addText('Date & Time:', ['bold' => true, 'size' => 10]);
            $activityTable->addCell(6500)->addText($activity->created_at->format('M d, Y H:i:s'), ['size' => 10]);

            $activityTable->addRow();
            $activityTable->addCell(2500)->addText('Performed By:', ['bold' => true, 'size' => 10]);
            $activityTable->addCell(6500)->addText(($activity->user->name ?? 'System') .
                ($activity->user_role ? " ({$activity->user_role})" : ''), ['size' => 10]);

            if ($activity->affected_user_id) {
                $activityTable->addRow();
                $activityTable->addCell(2500)->addText('Affected User:', ['bold' => true, 'size' => 10]);
                $activityTable->addCell(6500)->addText($activity->affectedUser->name ?? 'Unknown', ['size' => 10]);
            }

            $activityTable->addRow();
            $activityTable->addCell(2500)->addText('Description:', ['bold' => true, 'size' => 10]);
            $activityTable->addCell(6500)->addText($activity->description, ['size' => 10]);

            $activityTable->addRow();
            $activityTable->addCell(2500)->addText('Priority:', ['bold' => true, 'size' => 10]);
            $activityTable->addCell(6500)->addText(ucfirst($activity->priority_level), ['size' => 10]);

            if ($activity->old_values && !empty($activity->old_values)) {
                $activityTable->addRow();
                $activityTable->addCell(2500)->addText('Previous Values:', ['bold' => true, 'size' => 10]);
                $activityTable->addCell(6500)->addText($this->formatValuesForWord($activity->old_values), ['size' => 10]);
            }

            if ($activity->new_values && !empty($activity->new_values)) {
                $activityTable->addRow();
                $activityTable->addCell(2500)->addText('New Values:', ['bold' => true, 'size' => 10]);
                $activityTable->addCell(6500)->addText($this->formatValuesForWord($activity->new_values), ['size' => 10]);
            }

            if ($activity->metadata && !empty($activity->metadata)) {
                $activityTable->addRow();
                $activityTable->addCell(2500)->addText('Additional Info:', ['bold' => true, 'size' => 10]);
                $activityTable->addCell(6500)->addText($this->formatValuesForWord($activity->metadata), ['size' => 10]);
            }

            $section->addTextBreak(1);
        }

        // Footer
        $section->addTextBreak(2);
        $section->addText("Report generated on " . now()->format('M d, Y H:i:s') . " by " . Auth::user()->name,
            ['size' => 9, 'italic' => true, 'color' => '666666']);

        // Save and download
        $filename = "job-{$job->id}-history-" . now()->format('Y-m-d-H-i-s') . ".docx";
        $tempFile = tempnam(sys_get_temp_dir(), 'job_history');

        $writer = IOFactory::createWriter($phpWord, 'Word2007');
        $writer->save($tempFile);

        return response()->download($tempFile, $filename)->deleteFileAfterSend(true);
    }

    /**
     * Get activity data for timeline visualization (AJAX).
     */
    public function getTimelineData(Job $job, Request $request)
    {
        // Check company access
        if ($job->company_id !== Auth::user()->company_id) {
            abort(403);
        }

        $activities = JobActivityLog::where('job_id', $job->id)
            ->with(['user', 'affectedUser'])
            ->orderBy('created_at', 'asc')
            ->get();

        $timelineData = $activities->map(function ($activity) {
            return [
                'id' => $activity->id,
                'date' => $activity->created_at->toISOString(),
                'title' => ucfirst(str_replace('_', ' ', $activity->activity_type)),
                'description' => $activity->description,
                'category' => $activity->activity_category,
                'user' => $activity->user->name ?? 'System',
                'user_role' => $activity->user_role,
                'is_major' => $activity->is_major_activity,
                'priority' => $activity->priority_level,
                'icon' => $activity->activity_icon,
                'badge_class' => $activity->priority_badge,
            ];
        });

        return response()->json($timelineData);
    }

    /**
     * Format array values for Word document display.
     */
    private function formatValuesForWord($values)
    {
        if (empty($values)) {
            return 'None';
        }

        $formatted = [];
        foreach ($values as $key => $value) {
            if (is_array($value)) {
                $value = implode(', ', $value);
            }
            $formatted[] = ucfirst(str_replace('_', ' ', $key)) . ': ' . $value;
        }

        return implode(' | ', $formatted);
    }
}
