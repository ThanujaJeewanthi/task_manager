<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Facades\Log as FacadesLog;



use App\Models\Log;
use App\Models\Page;
use App\Models\PageCategory;
use Illuminate\Http\Request;
use App\Models\UserRoleDetail;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'username' => 'required',
            'password' => 'required',
        ]);
        FacadesLog::info('Login attempt', ['username' => $request->username]);
       Log::create([
    'action' => 'login attempt',
    'user_id' => null,
    'user_role_id' => null,
    'ip_address' => $request->ip(),
    'description' => 'Login attempt with username: ' . $request->username,
]);



        if (Auth::attempt($credentials)) {
            $user = Auth::user();

            $userRole = $user->userRole;
            if (!$userRole || $userRole->active != 1) {
                Auth::logout();
                FacadesLog::warning('Login denied due to inactive role', [
                    'user_id' => $user->id,
                    'role' => $userRole ? $userRole->name : 'no role',
                    'active' => $userRole ? $userRole->active : 'N/A'
                ]);
                Log::create([
    'action' => 'login denied - inactive role',
    'user_id' => $user->id,
    'user_role_id' => $userRole ? $userRole->id : null,
    'ip_address' => $request->ip(),
    'description' => $user->username . ' login denied due to inactive role.',
]);


                return back()->withErrors([
                    'username' => 'Your account role is inactive. Please contact administrator.',
                ]);
            }

Log::create([
    'action' => 'login success',
    'user_id' => $user->id,
    'user_role_id' => $user->userRole->id ?? null,
    'ip_address' => $request->ip(),
    'description' => $user->username . ' successfully logged in.',
]);

           FacadesLog::info('User authenticated', ['user_id' => $user->id, 'role' => $user->userRole ? $user->userRole->name : 'no role']);

            $request->session()->regenerate();
            $roleName = strtolower($userRole->name);

            // Store user details in session
            $request->session()->put('user_id', $user->id);
            $request->session()->put('user_role_id', $userRole->id);
            $request->session()->put('user_role_name', $roleName);
            $request->session()->put('user_role', $roleName);

            // Fetch user role details
            $userRoleDetails = UserRoleDetail::where('user_role_id', $userRole->id)
                ->where('status', 'allow')
                ->with(['page', 'pageCategory'])
                ->get();

            // Debug: Check if $userRoleDetails is empty
        FacadesLog::info('User Role Details', ['user_role_details' => $userRoleDetails->toArray()]);

            $categorizedPages = [];
            foreach ($userRoleDetails as $detail) {
                $categoryId = $detail->pageCategory->id;
                $categoryName = $detail->pageCategory->name;

                if (!isset($categorizedPages[$categoryId])) {
                    $categorizedPages[$categoryId] = [
                        'name' => $categoryName,
                        'pages' => []
                    ];
                }

                $categorizedPages[$categoryId]['pages'][] = $detail->page;
            }

            // Debug: Log the categorized pages array
            FacadesLog::info('Categorized Pages', ['categorized_pages' => $categorizedPages]);

            // Store in session
            $request->session()->put('categorized_pages', $categorizedPages);

            // Debug: Confirm session storage
            FacadesLog::info('Session Data Stored', ['session_categorized_pages' => $request->session()->get('categorized_pages')]);

            if ($roleName) {
                return redirect()->route($roleName . '.dashboard');
            } else {
                return redirect()->route('dashboard');
            }
        }
        Log::create([
    'action' => 'login failed',
    'user_id' => null,
    'user_role_id' => null,
    'ip_address' => $request->ip(),
    'description' => 'Failed login attempt with username: ' . $request->username,
]);


        return back()->withErrors([
            'username' => 'The provided credentials do not match our records.',
        ]);
    }

   public function logout(Request $request)
{
    $user = Auth::user();

    if ($user) {
        Log::create([
            'action' => 'logout',
            'user_id' => $user->id,
            'user_role_id' => $user->userRole->id ?? null,
            'ip_address' => $request->ip(),
            'description' => $user->username . ' logged out.',
        ]);
    }

    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return redirect()->route('login.form');
}

}
