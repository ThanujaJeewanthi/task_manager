<?php


use Illuminate\Support\Facades\Auth;

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PageController;



use App\Http\Controllers\UserController;

use App\Http\Controllers\Job\JobController;
use App\Http\Controllers\UserRoleController;
use App\Http\Controllers\PermissionController;
use App\Http\Controllers\Job\JobTypeController;
use App\Http\Controllers\Auth\ProfileController;
use App\Http\Controllers\PageCategoryController;
use App\Http\Controllers\Job\JobOptionController;

use App\Http\Controllers\EmployeeTaskController;

use App\Http\Controllers\Task\TaskExtensionController;
use App\Http\Controllers\Dashboard\AdminDashboardController;
use App\Http\Controllers\Dashboard\CommonDashboardController;
use App\Http\Controllers\Dashboard\EmployeeDashboardController;
use App\Http\Controllers\Dashboard\EngineerDashboardController;
use App\Http\Controllers\Dashboard\SuperAdminDashboardController;
use App\Http\Controllers\Dashboard\SupervisorDashboardController;
use App\Http\Controllers\Dashboard\TechnicalOfficerDashboardController;

// Authentication routes
//Auth::routes();


Route::middleware(['auth'])->group(function () {
    // Default route - Common Dashboard (redirects based on role)
    Route::get('/', [CommonDashboardController::class, 'index'])
        ->name('dashboard');

    // Super Admin Dashboard
    Route::get('/superadmin/dashboard', [SuperAdminDashboardController::class, 'index'])
        ->name('superadmin.dashboard')
        ->middleware('role.permission:1.2');

    // Company Admin Dashboard
    Route::get('/admin/dashboard', [AdminDashboardController::class, 'index'])
        ->name('admin.dashboard')
        ->middleware('role.permission:1.3');

    // Employee Dashboard
    Route::get('/employee/dashboard', [EmployeeDashboardController::class, 'index'])
        ->name('employee.dashboard')
        ->middleware('role.permission:1.4');

    // Engineer Dashboard
    Route::get('/engineer/dashboard', [EngineerDashboardController::class, 'index'])
        ->name('engineer.dashboard')
        ->middleware('role.permission:1.5');

    // Technical Officer Dashboard
    Route::get('/technicalofficer/dashboard', [TechnicalOfficerDashboardController::class, 'index'])
        ->name('technicalofficer.dashboard')
        ->middleware('role.permission:1.6');

    // Supervisor Dashboard
    Route::get('/supervisor/dashboard', [SupervisorDashboardController::class, 'index'])
        ->name('supervisor.dashboard')
        ->middleware('role.permission:1.7');
});

// API routes for dashboard functionality
Route::middleware(['auth'])->group(function () {
    // Super Admin Dashboard API
    Route::get('/superadmin/dashboard/chart-data', [SuperAdminDashboardController::class, 'getChartData'])
        ->name('superadmin.dashboard.chart-data')
        ->middleware('role.permission:1.2');

    // Admin Dashboard API
    Route::get('/admin/dashboard/quick-stats', [AdminDashboardController::class, 'getQuickStats'])
        ->name('admin.dashboard.quick-stats')
        ->middleware('role.permission:1.3');

    Route::get('/admin/dashboard/job-status', [AdminDashboardController::class, 'getJobStatusUpdate'])
        ->name('admin.dashboard.job-status')
        ->middleware('role.permission:1.3');

    // Employee Dashboard API
    Route::post('/employee/tasks/{task}/status', [EmployeeDashboardController::class, 'updateTaskStatus'])
        ->name('employee.tasks.update-status')
        ->middleware('role.permission:1.4');

    Route::post('/employee/jobs/{job}/status', [EmployeeDashboardController::class, 'updateJobStatus'])
        ->name('employee.jobs.update-status')
        ->middleware('role.permission:1.4');

    Route::get('/employee/tasks/{task}/details', [EmployeeDashboardController::class, 'getTaskDetails'])
        ->name('employee.tasks.details')
        ->middleware('role.permission:1.4');

    // Engineer Dashboard API
    Route::get('/engineer/dashboard/quick-stats', [EngineerDashboardController::class, 'getQuickStats'])
        ->name('engineer.dashboard.quick-stats')
        ->middleware('role.permission:1.5');

    Route::post('/engineer/jobs/{job}/approve', [EngineerDashboardController::class, 'approveJob'])
        ->name('engineer.jobs.approve')
        ->middleware('role.permission:1.5');

    Route::get('/api/engineer/notification-counts', [EngineerDashboardController::class, 'getNotificationCounts'])
        ->name('engineer.notification-counts')
        ->middleware('role.permission:1.5');

    // Technical Officer Dashboard API
    Route::get('/technicalofficer/dashboard/quick-stats', [TechnicalOfficerDashboardController::class, 'getQuickStats'])
        ->name('technicalofficer.dashboard.quick-stats')
        ->middleware('role.permission:1.6');

    Route::post('/technicalofficer/jobs/{job}/complete', [TechnicalOfficerDashboardController::class, 'completeJob'])
        ->name('technicalofficer.jobs.complete')
        ->middleware('role.permission:1.6');

    Route::post('/technicalofficer/jobs/{job}/status', [TechnicalOfficerDashboardController::class, 'updateJobStatus'])
        ->name('technicalofficer.jobs.status')
        ->middleware('role.permission:1.6');

    // Supervisor Dashboard API
    Route::get('/supervisor/dashboard/quick-stats', [SupervisorDashboardController::class, 'getQuickStats'])
        ->name('supervisor.dashboard.quick-stats')
        ->middleware('role.permission:1.7');

    Route::post('/supervisor/jobs/{job}/assign', [SupervisorDashboardController::class, 'assignJob'])
        ->name('supervisor.jobs.assign')
        ->middleware('role.permission:1.7');

    Route::post('/supervisor/jobs/bulk-assign', [SupervisorDashboardController::class, 'bulkAssignJobs'])
        ->name('supervisor.jobs.bulk-assign')
        ->middleware('role.permission:1.7');

    Route::get('/supervisor/jobs/assignment-data', [SupervisorDashboardController::class, 'getJobAssignmentData'])
        ->name('supervisor.jobs.assignment-data')
        ->middleware('role.permission:1.7');
});



Route::get('/login', [\App\Http\Controllers\Auth\LoginController::class, 'showLoginForm'])->name('login.form');
Route::post('/login', [\App\Http\Controllers\Auth\LoginController::class, 'login'])->name('login');
Route::get('/register', [\App\Http\Controllers\Auth\RegisterController::class, 'showRegistrationForm'])->name('register.form');
Route::post('/register', [\App\Http\Controllers\Auth\RegisterController::class, 'register'])->name('register');
Route::post('/logout', [\App\Http\Controllers\Auth\LoginController::class, 'logout'])->name('logout');
Route::get('/profile', [ProfileController::class, 'index'])->name('profile');
Route::get('/profile/edit', [ProfileController::class, 'edit'])->name('profile.edit');
Route::put('/profile/update', [ProfileController::class, 'updateProfile'])->name('profile.update');
Route::delete('/profile/delete', [ProfileController::class, 'deleteProfile'])->name('profile.delete');
Route::post('/profile/change-password', [ProfileController::class, 'changePassword'])->name('profile.change-password');


// Admin routes
Route::prefix('admin')->name('admin.')->middleware(['auth'])->group(function () {

    // Page Categories
    Route::get('/page-categories', [PageCategoryController::class, 'index'])
        ->name('page-categories.index')
        ->middleware('role.permission:2.1');
    Route::get('/page-categories/create', [PageCategoryController::class, 'create'])
        ->name('page-categories.create')
        ->middleware('role.permission:2.2');
    Route::post('/page-categories', [PageCategoryController::class, 'store'])
        ->name('page-categories.store')
        ->middleware('role.permission:2.2');
    Route::get('/page-categories/{pageCategory}/edit', [PageCategoryController::class, 'edit'])
        ->name('page-categories.edit')
        ->middleware('role.permission:2.3');
    Route::put('/page-categories/{pageCategory}', [PageCategoryController::class, 'update'])
        ->name('page-categories.update')
        ->middleware('role.permission:2.3');
    Route::delete('/page-categories/{pageCategory}', [PageCategoryController::class, 'destroy'])
        ->name('page-categories.destroy')
        ->middleware('role.permission:2.1');
    // Pages
    Route::get('/pages', [PageController::class, 'index'])->name('pages.index')->middleware('role.permission:2.4');
    Route::get('/pages/create', [PageController::class, 'create'])->name('pages.create')->middleware('role.permission:2.5');
    Route::post('/pages', [PageController::class, 'store'])->name('pages.store');
    Route::get('/pages/{page}/edit', [PageController::class, 'edit'])->name('pages.edit')->middleware('role.permission:2.6');
    Route::put('/pages/{page}', [PageController::class, 'update'])->name('pages.update');
    Route::delete('/pages/{page}', [PageController::class, 'destroy'])->name('pages.destroy');

    // User Roles
    Route::get('/roles', [UserRoleController::class, 'index'])->name('roles.index')->middleware('role.permission:3.1');
    Route::get('/roles/create', [UserRoleController::class, 'create'])->name('roles.create')->middleware('role.permission:3.2');
    Route::post('/roles', [UserRoleController::class, 'store'])->name('roles.store');
    Route::get('/roles/{roleId}/edit', [UserRoleController::class, 'edit'])->name('roles.edit')->middleware('role.permission:3.3');
    Route::put('/roles/{roleId}', [UserRoleController::class, 'update'])->name('roles.update');
    Route::delete('/roles/{roleId}', [UserRoleController::class, 'destroy'])->name('roles.destroy');

    // Permission management
    Route::get('/permissions/manage/{roleId}', [PermissionController::class, 'manage'])->name('permissions.manage')->middleware('role.permission:3.4');
    Route::put('/permissions/update/{roleId}', [PermissionController::class, 'update'])->name('permissions.update');
    Route::post('/permissions/search', [PermissionController::class, 'search'])->name('permissions.search');

    // Users
    Route::get('/users', [UserController::class, 'index'])->name('users.index')->middleware('role.permission:4.1');
    Route::get('/users/create', [UserController::class, 'create'])->name('users.create')->middleware('role.permission:4.2');
    Route::post('/users', [UserController::class, 'store'])->name('users.store');
    Route::get('/users/{userId}/edit', [UserController::class, 'edit'])->name('users.edit')->middleware('role.permission:4.3');
    Route::put('/users/{userId}', [UserController::class, 'update'])->name('users.update');
    Route::delete('/users/{userId}', [UserController::class, 'delete'])->name('users.delete');
});

Route::middleware(['auth'])->group(function () {

Route::get('/logs', [App\Http\Controllers\LogController::class, 'index'])->name('logs.index')->middleware('role.permission:13.1');
    Route::get('/logs/{id}', [App\Http\Controllers\LogController::class, 'show'])->name('logs.show')->middleware('role.permission:13.2');
    Route::post('/logs/clear', [App\Http\Controllers\LogController::class, 'clear'])->name('logs.clear')->middleware('role.permission:13.2');
});

//companies routes
Route::prefix('companies')->name('companies.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\CompanyController::class, 'index'])->name('index')->middleware('role.permission:5.1');
    Route::get('/create', [\App\Http\Controllers\CompanyController::class, 'create'])->name('create')->middleware('role.permission:5.2');
    Route::get('/{company}', [\App\Http\Controllers\CompanyController::class, 'show'])->name('show')->middleware('role.permission:5.3');
    Route::post('/', [\App\Http\Controllers\CompanyController::class, 'store'])->name('store')->middleware('role.permission:5.2');
    Route::get('/{company}/edit', [\App\Http\Controllers\CompanyController::class, 'edit'])->name('edit')->middleware('role.permission:5.4');
    Route::put('/{company}', [\App\Http\Controllers\CompanyController::class, 'update'])->name('update')->middleware('role.permission:5.4');
    Route::delete('/{company}', [\App\Http\Controllers\CompanyController::class, 'destroy'])->name('destroy')->middleware('role.permission:5.4');
});

//clients
Route::prefix('clients')->name('clients.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\ClientController::class, 'index'])->name('index')->middleware('role.permission:7.1');
    Route::get('/create', [\App\Http\Controllers\ClientController::class, 'create'])->name('create')->middleware('role.permission:7.2');
    Route::post('/', [\App\Http\Controllers\ClientController::class, 'store'])->name('store')->middleware('role.permission:7.2');
    Route::get('/{client}/edit', [\App\Http\Controllers\ClientController::class, 'edit'])->name('edit')->middleware('role.permission:7.3');
    Route::put('/{client}', [\App\Http\Controllers\ClientController::class, 'update'])->name('update')->middleware('role.permission:7.3');
    Route::delete('/{client}', [\App\Http\Controllers\ClientController::class, 'destroy'])->name('destroy')->middleware('role.permission:7.3');
});
//employees
Route::prefix('employees')->name('employees.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\EmployeeController::class, 'index'])->name('index')->middleware('role.permission:6.1');
    Route::get('/create', [\App\Http\Controllers\EmployeeController::class, 'create'])->name('create')->middleware('role.permission:6.2');
    Route::get('/{employee}', [\App\Http\Controllers\EmployeeController::class, 'show'])->name('show')->middleware('role.permission:6.3');
    Route::post('/', [\App\Http\Controllers\EmployeeController::class, 'store'])->name('store')->middleware('role.permission:6.2');
    Route::get('/{employee}/edit', [\App\Http\Controllers\EmployeeController::class, 'edit'])->name('edit')->middleware('role.permission:6.4');
    Route::put('/{employee}', [\App\Http\Controllers\EmployeeController::class, 'update'])->name('update')->middleware('role.permission:6.4');
    Route::delete('/{employee}', [\App\Http\Controllers\EmployeeController::class, 'destroy'])->name('destroy')->middleware('role.permission:6.4');
});
//jobs
Route::prefix('jobs')->name('jobs.')->middleware(['auth'])->group(function () {
    Route::get('/', [JobController::class, 'index'])->name('index')->middleware('role.permission:11.7');
    Route::get('/create', [JobController::class, 'create'])->name('create')->middleware('role.permission:11.8');
    Route::post('/', [JobController::class, 'store'])->name('store')->middleware('role.permission:11.8');
    Route::get('/{job}/edit', [JobController::class, 'edit'])->name('edit')->middleware('role.permission:11.9');
    Route::put('/{job}', [JobController::class, 'update'])->name('update')->middleware('role.permission:11.9');
    Route::delete('/{job}', [JobController::class, 'destroy'])->name('destroy')->middleware('role.permission:11.9');
    Route::get('/{job}', [JobController::class, 'show'])->name('show')->middleware('role.permission:11.10');
});
//job options
Route::prefix('job-options')->name('job-options.')->middleware(['auth'])->group(function () {
    Route::get('/', [JobOptionController::class, 'index'])->name('index')->middleware('role.permission:11.4');
    Route::get('/create', [JobOptionController::class, 'create'])->name('create')->middleware('role.permission:11.5');
    Route::post('/', [JobOptionController::class, 'store'])->name('store')->middleware('role.permission:11.5');
    Route::get('/{jobOption}/edit', [JobOptionController::class, 'edit'])->name('edit')->middleware('role.permission:11.6');
    Route::put('/{jobOption}', [JobOptionController::class, 'update'])->name('update')->middleware('role.permission:11.6');
    Route::delete('/{jobOption}', [JobOptionController::class, 'destroy'])->name('destroy')->middleware('role.permission:11.6');
});

Route::prefix('job-types')->name('job-types.')->middleware(['auth'])->group(function () {
    Route::get('/', [JobTypeController::class, 'index'])->name('index')->middleware('role.permission:11.1');
    Route::get('/create', [JobTypeController::class, 'create'])->name('create')->middleware('role.permission:11.2');
    Route::post('/', [JobTypeController::class, 'store'])->name('store')->middleware('role.permission:11.2');
    Route::get('/{jobType}/edit', [JobTypeController::class, 'edit'])->name('edit')->middleware('role.permission:11.3');
    Route::put('/{jobType}', [JobTypeController::class, 'update'])->name('update')->middleware('role.permission:11.3');
    Route::delete('/{jobType}', [JobTypeController::class, 'destroy'])->name('destroy')->middleware('role.permission:11.3');
});

//items
Route::prefix('items')->name('items.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\ItemController::class, 'index'])->name('index')->middleware('role.permission:10.1');
    Route::get('/create', [\App\Http\Controllers\ItemController::class, 'create'])->name('create')->middleware('role.permission:10.2');
    Route::post('/', [\App\Http\Controllers\ItemController::class, 'store'])->name('store')->middleware('role.permission:10.2');
    Route::get('/{item}/edit', [\App\Http\Controllers\ItemController::class, 'edit'])->name('edit')->middleware('role.permission:10.3');
    Route::put('/{item}', [\App\Http\Controllers\ItemController::class, 'update'])->name('update')->middleware('role.permission:10.3');
    Route::delete('/{item}', [\App\Http\Controllers\ItemController::class, 'destroy'])->name('destroy')->middleware('role.permission:10.3');
});
//equipments
Route::prefix('equipments')->name('equipments.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\EquipmentController::class, 'index'])->name('index')->middleware('role.permission:9.1');
    Route::get('/create', [\App\Http\Controllers\EquipmentController::class, 'create'])->name('create')->middleware('role.permission:9.2');
    Route::post('/', [\App\Http\Controllers\EquipmentController::class, 'store'])->name('store')->middleware('role.permission:9.2');
    Route::get('/{equipment}/edit', [\App\Http\Controllers\EquipmentController::class, 'edit'])->name('edit')->middleware('role.permission:9.3');
    Route::put('/{equipment}', [\App\Http\Controllers\EquipmentController::class, 'update'])->name('update')->middleware('role.permission:9.3');
    Route::delete('/{equipment}', [\App\Http\Controllers\EquipmentController::class, 'destroy'])->name('destroy')->middleware('role.permission:9.3');
});
//suppliers
Route::prefix('suppliers')->name('suppliers.')->middleware(['auth'])->group(function () {
    Route::get('/', [\App\Http\Controllers\SupplierController::class, 'index'])->name('index')->middleware('role.permission:8.1');
    Route::get('/create', [\App\Http\Controllers\SupplierController::class, 'create'])->name('create')->middleware('role.permission:8.2');
    Route::post('/', [\App\Http\Controllers\SupplierController::class, 'store'])->name('store')->middleware('role.permission:8.2');
    Route::get('/{supplier}/edit', [\App\Http\Controllers\SupplierController::class, 'edit'])->name('edit')->middleware('role.permission:8.3');
    Route::put('/{supplier}', [\App\Http\Controllers\SupplierController::class, 'update'])->name('update')->middleware('role.permission:8.3');
    Route::delete('/{supplier}', [\App\Http\Controllers\SupplierController::class, 'destroy'])->name('destroy')->middleware('role.permission:8.3');
});

Route::middleware(['auth'])->group(function () {
    // Job Assignment Management
    Route::get('/job-assignments', [\App\Http\Controllers\Job\JobAssignmentController::class, 'index'])
        ->name('job-assignments.index')
        ->middleware('role.permission:11.16');

    Route::get('/jobs/{job}/assign', [\App\Http\Controllers\Job\JobAssignmentController::class, 'create'])
        ->name('job-assignments.create')
        ->middleware('role.permission:11.17');

    Route::post('/jobs/{job}/assign', [\App\Http\Controllers\Job\JobAssignmentController::class, 'store'])
        ->name('job-assignments.store')
        ->middleware('role.permission:11.17');

    Route::get('/job-assignments/{assignment}', [\App\Http\Controllers\Job\JobAssignmentController::class, 'show'])
        ->name('job-assignments.show')
        ->middleware('role.permission:11.18');

    Route::post('/job-assignments/{assignment}/status', [\App\Http\Controllers\Job\JobAssignmentController::class, 'updateStatus'])
        ->name('job-assignments.update-status')
        ->middleware('role.permission:11.19');

    Route::delete('/job-assignments/{assignment}', [\App\Http\Controllers\Job\JobAssignmentController::class, 'destroy'])
        ->name('job-assignments.destroy')
        ->middleware('role.permission:11.19');

    Route::get('/my-assignments', [\App\Http\Controllers\Job\JobAssignmentController::class, 'myAssignments'])
        ->name('job-assignments.my-assignments')
        ->middleware('role.permission:11.20');
});


//tasks
Route::prefix('jobs')->name('jobs.tasks.')->middleware(['auth'])->group(function () {
    Route::get('/{job}/tasks/', [JobController::class, 'index'])->name('index')->middleware('role.permission:11.11');
    Route::get('/{job}/tasks/create', [JobController::class, 'createTask'])->name('create')->middleware('role.permission:11.12');
    Route::post('/{job}/tasks', [JobController::class, 'storeTask'])->name('store')->middleware('role.permission:11.12');
    Route::get('/{job}/tasks/{task}/edit', [JobController::class, 'editTask'])->name('edit')->middleware('role.permission:11.13');
    Route::put('/{job}/tasks/{task}', [JobController::class, 'updateTask'])->name('update')->middleware('role.permission:11.13');
    Route::delete('/{job}/tasks/{task}', [JobController::class, 'destroyTask'])->name('destroy')->middleware('role.permission:11.13');

});

Route::prefix('jobs')->name('jobs.items.')->middleware(['auth'])->group(function () {
    // Item addition routes
    Route::get('/{job}/add-items', [JobController::class, 'addItems'])->name('add')->middleware('role.permission:11.14');
    Route::post('/{job}/store-items', [JobController::class, 'storeItems'])->name('store')->middleware('role.permission:11.14');

    // Job approval routes
    Route::get('/{job}/approval', [JobController::class, 'showApproval'])->name('show-approval')->middleware('role.permission:11.15');
    Route::post('/{job}/process-approval', [JobController::class, 'processApproval'])->name('process-approval')->middleware('role.permission:11.15');

});


Route::middleware(['auth'])->group(function () {
    Route::get('/jobs/job-types/{jobTypeId}/options', [JobController::class, 'getJobTypeOptions'])
        ->name('jobs.job-type-options');


    Route::get('jobs/{job}/copy', [JobController::class, 'copy'])
        ->name('jobs.copy')
        ->middleware('role.permission:11.21');

    Route::post('jobs/{job}/copy', [JobController::class, 'storeCopy'])
        ->name('jobs.copy.store')
        ->middleware('role.permission:11.21');

    Route::get('jobs/{job}/extend-task', [JobController::class, 'extendTask'])
        ->name('jobs.extend-task')
        ->middleware('role.permission:11.22');

    Route::post('jobs/{job}/extend-task', [JobController::class, 'storeExtendTask'])
        ->name('jobs.extend-task.store')
        ->middleware('role.permission:11.22');
});

Route::middleware(['auth'])->group(function () {
    // Employee can request task extension
    Route::get('/tasks/{task}/request-extension', [TaskExtensionController::class, 'create'])
        ->name('tasks.extension.create')
        ->middleware('role.permission:12.1');

    Route::post('/tasks/{task}/request-extension', [TaskExtensionController::class, 'requestTaskExtension'])
        ->name('tasks.extension.store')
        ->middleware('role.permission:12.1');

    // View own extension requests
    Route::get('/my-extension-requests', [TaskExtensionController::class, 'myRequests'])
        ->name('tasks.extension.my-requests')
        ->middleware('role.permission:12.2');
});

// Task Extension Approval routes for Supervisors, Technical Officers, and Engineers
Route::middleware(['auth'])->group(function () {
    // View pending extension requests for approval
    Route::get('/extension-requests', [TaskExtensionController::class, 'index'])
        ->name('tasks.extension.index')
        ->middleware('role.permission:12.3'); // Technical Officer, Supervisor, and Engineer permissions

    // Show specific extension request
    Route::get('/extension-requests/{extensionRequest}', [TaskExtensionController::class, 'show'])
        ->name('tasks.extension.show')
        ->middleware('role.permission:12.4');

    // Approve or reject extension request
    Route::post('/extension-requests/{extensionRequest}/approve', [TaskExtensionController::class, 'approve'])
        ->name('tasks.extension.approve')
        ->middleware('role.permission:12.5');

    Route::post('/extension-requests/{extensionRequest}/reject', [TaskExtensionController::class, 'reject'])
        ->name('tasks.extension.reject')
        ->middleware('role.permission:12.5');

    // API endpoint for getting pending extension count (for dashboards)
    Route::get('/api/extension-requests/pending-count', [TaskExtensionController::class, 'getPendingCount'])
        ->name('tasks.extension.pending-count')
        ->middleware('role.permission:12.6 ');
});

// Add these routes to routes/web.php

// Employee Task Management Routes
Route::middleware(['auth'])->group(function () {
    Route::post('/tasks/{task}/start', [EmployeeTaskController::class, 'startTask'])
        ->name('tasks.start');


    Route::post('/tasks/{task}/complete', [EmployeeTaskController::class, 'completeTask'])
        ->name('tasks.complete');

});

// Engineer Job Review Routes
Route::middleware(['auth'])->group(function () {
    Route::get('/jobs/{job}/review', [JobController::class, 'showReview'])
        ->name('jobs.review');

    Route::post('/jobs/{job}/review', [JobController::class, 'processReview'])
        ->name('jobs.review.process');
});

Route::middleware(['auth'])->group(function () {
    Route::get('/jobs/{job}/timeline-data', [JobController::class, 'getTimelineJson'])
        ->name('jobs.timeline-data');

    Route::get('/jobs/{job}/tasks/{task}/details', [JobController::class, 'getTaskDetails'])
        ->name('jobs.task-details');
});



Route::fallback(function () {
    return 'Fallback';
});


use App\Http\Controllers\Job\JobHistoryController;

// Job History and Activity Logging Routes
Route::middleware(['auth'])->group(function () {

    // Job History Timeline
    Route::get('/jobs/{job}/history', [JobHistoryController::class, 'index'])
        ->name('jobs.history.index')
        ->middleware('role.permission:11.23'); // Add this permission to your seeds

    // View specific activity details
    Route::get('/jobs/{job}/history/{activity}', [JobHistoryController::class, 'show'])
        ->name('jobs.history.show')
        ->middleware('role.permission:11.24'); // Add this permission to your seeds

        Route::get('/jobs/{job}/history/export', [JobHistoryController::class, 'export'])
        ->name('jobs.history.export')
        ->middleware('role.permission:11.24');

    // Export job history as PDF
    Route::get('/jobs/{job}/history/export/pdf', [JobHistoryController::class, 'exportPdf'])
        ->name('jobs.history.export.pdf')
        ->middleware('role.permission:11.24'); // Add this permission to your seeds

    // Export job history as Word document
    Route::get('/jobs/{job}/history/export/word', [JobHistoryController::class, 'exportWord'])
        ->name('jobs.history.export.word')
        ->middleware('role.permission:11.24'); // Same permission as PDF export

    // AJAX endpoint for timeline data (for visual timeline components)
    Route::get('/jobs/{job}/history/timeline-data', [JobHistoryController::class, 'getTimelineData'])
        ->name('jobs.history.timeline-data')
        ->middleware('role.permission:11.24'); // Same as view permission

});




// Route::get('/thanuu', function () {
//     return view('test');
// })->name('thanuu')->middleware('role.permission:8.3');

// Route::get('/test', function () {
//     return view('test');
// })->name('test')->middleware('role.permission:7.1');
