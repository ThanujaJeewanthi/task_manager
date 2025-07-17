<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\UserRole;
use App\Models\Log;
use App\Models\Company;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;

class RegisterController extends Controller
{
    /**
     * Show the registration form with user roles and companies.
     *
     * @return \Illuminate\View\View
     */
    public function showRegistrationForm()
    {
        $companies = Company::where('active', true)->get();
        $userRoles = UserRole::where('active', true)->get();
        $currentUser = Auth::user();
        return view('auth.register', compact('userRoles', 'companies', 'currentUser'));
    }

    /**
     * Handle a registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function register(Request $request)
    {
        $isFirstUser = User::count() === 0;
        $currentUser = Auth::user();
        $isSuperAdmin = $currentUser && strtolower(UserRole::find($currentUser->user_role_id)->name) === 'super admin';

        $rules = [
            'username' => ['required', 'string', 'max:255', 'unique:users'],
            'name' => ['required', 'string', 'max:255'],
            'email' => ['nullable', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
            'phone_number' => ['required', 'string', 'max:20'],
            'user_role_id' => ['required', 'exists:user_roles,id'],
        ];

        // Add company_id validation only for Super Admin
        if ($isSuperAdmin) {
            $rules['company_id'] = ['required', 'exists:companies,id'];
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return redirect()->back()
                ->withErrors($validator)
                ->withInput($request->except('password'));
        }

        try {
            DB::beginTransaction();

            $userRole = UserRole::findOrFail($request->user_role_id);

            // Determine company_id based on user role
            $companyId = $isSuperAdmin ? $request->company_id : ($currentUser ? $currentUser->company_id : null);

            if (!$companyId && !$isFirstUser) {
                throw new \Exception('Company ID is required.');
            }

            // Create user
            $user = User::create([
                'username' => $request->username,
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'phone_number' => $request->phone_number,
                'user_role_id' => $request->user_role_id,
                'company_id' => $companyId,
                'active' => true,
                'created_by' => $currentUser ? $currentUser->id : null,
            ]);

            // Log user creation
            if ($currentUser) {
                Log::create([
                    'action' => 'user_registered',
                    'user_id' => $currentUser->id,
                    'user_role_id' => $currentUser->user_role_id,
                    'ip_address' => $request->ip(),
                    'description' => "Registered new user: {$user->username} with role: {$userRole->name}",
                    'active' => true,
                ]);
            }

            DB::commit();

            if ($isFirstUser) {
                // First user registration - log them in
                Auth::login($user);
                return redirect()->route('dashboard')->with('success', 'Registration successful! Welcome to the system.');
            } else {
                // Admin creating user
                return redirect()->route('admin.users.index')->with('success', 'User registered successfully.');
            }

        } catch (\Exception $e) {
            DB::rollBack();
            return redirect()->back()
                ->with('error', 'Registration failed: ' . $e->getMessage())
                ->withInput($request->except('password'));
        }
    }
}