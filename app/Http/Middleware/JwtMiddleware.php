<?php

namespace App\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Exception;

class JWTMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken(); // Lấy token từ header Authorization: Bearer xxx

        if (!$token) {
            return response()->json(['message' => 'Token không được cung cấp'], 401);
        }

        try {
            $secret = config('jwt.secret');
            $algo = config('jwt.algorithm', 'HS256');

            $decoded = JWT::decode($token, new Key($secret, $algo));

            // Kiểm tra token hết hạn
            if (isset($decoded->exp) && $decoded->exp < time()) {
                return response()->json(['message' => 'Token đã hết hạn'], 401);
            }

            // Lưu payload vào request để controller hoặc service sử dụng
            $request->attributes->set('jwt_payload', $decoded);

        } catch (Exception $e) {
            return response()->json(['message' => 'Token không hợp lệ', 'error' => $e->getMessage()], 401);
        }

        return $next($request);
    }
}
