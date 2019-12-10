<?php
namespace App\Http\Middleware;

use Closure;
use Exception;
use App\User;
use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Illuminate\Support\Facades\Storage;

class JwtMiddleware
{
    public function handle($request, Closure $next, $guard = null)
    {
        $authorization = $request->header('Authorization');
        $token = substr($authorization, strlen('Bearer '));
        $pubKey = Storage::disk('local')->get('pub_key');

        if (!$token) {
            // Unauthorized response if token not there
            return response()->json([
                'error' => 'Token not provided.'
            ], 401);
        }
        try {
            $credentials = JWT::decode($token, $pubKey, ['RS256']);
        } catch (ExpiredException $e) {
            return response()->json([
                'error' => 'Provided token is expired.'
            ], 400);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'An error while decoding token.'
            ], 400);
        }
        $user = User::where('api_token', $credentials->sub)->first();

        if (empty($user)) {
            return response()->json('Not Authorized', 401);
        }

        $request->auth = $user;
        return $next($request);
    }
}
