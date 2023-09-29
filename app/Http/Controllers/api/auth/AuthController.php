<?php

namespace App\Http\Controllers\api\auth;

use App\Http\Controllers\api\BaseController;
use App\Models\User;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends BaseController
{
    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'c_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('HelpdeskManagement')->accessToken;
        $success['name'] =  $user->name;

        return $this->sendResponse($success, 'User register successfully.');
    }

    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        try {
            $data = [
                'grant_type' => 'password',
                'client_id' => config('auth.secrets.client_id'),
                'client_secret' => config('auth.secrets.client_secrets'),
                'username' => $request->username,
                'password' => $request->password
            ];

            $httpResponse = app()->handle(
                Request::create('/oauth/token', 'POST', $data)
            );

            if ($httpResponse->isOk()) {
                $res = $httpResponse->getContent();
                $res = json_decode($res, true);
                return $res;
            } else {
                return response()->json(['message' => 'Unauthorized'], 401);
            }
            return response($httpResponse, $httpResponse->status());
        } catch (Exception $ex) {
            return response()->json(
                ['message' => $ex->getMessage()],
                500
            );
        }
    }

    public function me(Request $request)
    {
        try {
            return response()->json($request->user('api'));
        } catch (Exception $ex) {
            return response()->json(
                ['message' => $ex->getMessage()],
                500
            );
        }
    }

    public function refreshToken(Request $request)
    {
        try {
            //code...

            $data = [
                'grant_type' => 'refresh_token',
                'client_id' => config('auth.secrets.client_id'),
                'client_secret' => config('auth.secrets.client_secrets'),
                'refresh_token' => $request->refresh_token,
                'scope' => ''
            ];
            $httpResponse = app()->handle(
                Request::create('/oauth/token', 'POST', $data)
            );

            if ($httpResponse->isOk()) {
                $res = $httpResponse->getContent();
                $res = json_decode($res, true);
                return $res;
            }

            return response($httpResponse, $httpResponse->status());
        } catch (\Exception $ex) {
            return response()->json(
                ['message' => $ex->getMessage()],
                500
            );
        }
    }

    public function logout(Request $request)
    {
        try {
            return response()->json(
                $request->user('api')
                    ->token()
                    ->revoke()
            );
        } catch (Exception $ex) {
            return response()->json(
                ['message' => $ex->getMessage()],
                500
            );
        }
    }
}
