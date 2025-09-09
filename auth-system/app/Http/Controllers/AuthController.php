<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function register(Request $request) {
        $validated = $request->validate(
            [
                'name'=>'required|string|max:255',
                'email'=>'required|string|max:255|email|unique:users',
                'password'=>'required|string|min:8|confirmed'
            ]
            );
        
        $validated['password'] = Hash::make($validated['password']);
        
        $user = User::create($validated);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user', 'token'), 201);

    }

    public function login (Request $request) {
        $credentials = $request->validate([
            'email'=>'required|email',
            'password'=>'required|string|min:8'
        ]);

        if (! $token = JWTAuth::attempt($credentials)){
            return response()->json(['error'=>'Invalid Credential'], 401);
        }

        return response()->json([
            'access_token'=>$token,
            'user'=>Auth::user()
        ]);
    }

    public function logout() {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message'=>'Logged out successfully']);
        }
        catch(\Exception $e){
            return response()->json(['error'=>'Failed to logout, token invalid or missing'], 400);
        }
    }

    public function refresh() {
        try {
            $token = JWTAuth::getToken();
            $newToken = JWTAuth::refresh($token);
            return response()->json([
                'access_token' => $newToken
            ]);
        }

        catch(JWTException $e) {
            return response()->json(['error' => 'Failed to refresh token'], 400);
        }
    }
}
