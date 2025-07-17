<?php
namespace App\Http\Controllers\Dashboard;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;

class CommonDashboardController extends Controller
{
    public function index()
    {
        $user = Auth::user();
        $userRole = strtolower($user->userRole->name ?? '');

        // Redirect based on user role
        switch ($userRole) {
            case 'super admin':
                return redirect()->route('superadmin.dashboard');
            case 'admin':
            case 'company admin':
                return redirect()->route('admin.dashboard');
            case 'employee':
                return redirect()->route('employee.dashboard');
            case 'engineer':
                return redirect()->route('engineer.dashboard');
            case 'supervisor':
                return redirect()->route('supervisor.dashboard');
            case 'technical officer':
                return redirect()->route('technicalofficer.dashboard');
            default:
                return redirect()->route('dashboard');
        }
    }
}