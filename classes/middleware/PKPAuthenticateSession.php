<?php

/**
 * @file classes/middleware/PKPAuthenticateSession.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class PKPAuthenticateSession
 *
 * @brief Monitor session data to control authentication flow 
 */

namespace PKP\middleware;

use Closure;
use PKP\config\Config;
use PKP\security\Validation;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;

class PKPAuthenticateSession extends \Illuminate\Session\Middleware\AuthenticateSession
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        // Sign the user back in from the "remember me" cookie, if any, before the session is first saved
        $this->guard()->user();

        $response = parent::handle($request, $next);

        if ($request->hasSession()
            && $request->user()
            && Config::getVar('security', 'session_check_ip')
            && ($loginIp = $request->session()->get('login_ip'))
            && $loginIp !== $request->ip()
        ) {
            $this->logout($request);
        }
        
        return $response;
    }
    
    /**
     * Log the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function logout($request)
    {
        // End this browser's session and remove its "remember me" cookie, as Laravel's AuthenticateSession
        // does, without cycling the token that keeps the user's other browsers remembered
        Auth::logoutCurrentDevice();

        $request->session()->invalidate();
        $request->session()->regenerateToken();
        app()->get('auth.driver')->updateSessionCookieToResponse();

        return $this->redirectTo($request);
    }

    /**
     * Get the path the user should be redirected to when their session is not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function redirectTo(Request $request)
    {
        Validation::redirectLogin();
    }
}
