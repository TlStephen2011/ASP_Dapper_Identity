import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';

@Injectable({
    providedIn: 'root'
})
export class AuthGuard implements CanActivate {
    constructor(private router: Router) {}

    canActivate(
        next: ActivatedRouteSnapshot,
        state: RouterStateSnapshot): boolean {
        const isLoggedIn = !!localStorage.getItem('jwt'); // Example, check if JWT exists

        if (isLoggedIn) {
            return true;
        } else {
            // Redirect to log in if not authenticated
            this.router.navigate(['/login']);
            return false;
        }
    }
}
