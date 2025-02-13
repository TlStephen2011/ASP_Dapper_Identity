import {Component, OnInit} from '@angular/core';
import {AuthService} from '../../services/auth.service';
import {GoogleSigninService} from '../../services/google-signin.service';
import {catchError, filter, of, switchMap, tap} from 'rxjs';
import {Router} from '@angular/router';

@Component({
    selector: 'app-login',
    standalone: false,

    templateUrl: './login.component.html',
    styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {

    isLoading = false;

    username: string = '';
    password: string = '';

    constructor(private authService: AuthService, private googleSigninService: GoogleSigninService, private router: Router) {
    }

    ngOnInit(): void {
        this.googleSigninService.googleToken$
            .pipe(
                filter(token => !!token),
                switchMap(token => this.googleSigninService.handleToken(token)),
                tap(jwtResponse => {
                    this.authService.handleToken(jwtResponse.jwtToken);
                    void this.router.navigate(['/home']);
                    this.isLoading = false;
                }),
                catchError(error => {
                    console.error(error);
                    return of(null);
                })
            )
            .subscribe();
    }

    onLoginSubmit() {
        this.authService.signin(this.username, this.password)
            .subscribe(x => {
                this.authService.handleToken(x.jwtToken);
                void this.router.navigate(['/home']);
            });
        console.log('Login submitted');
        // Handle the login logic here
    }

    onRegisterSubmit() {
        console.log('Register submitted');
        // Handle the registration logic here
    }

    googleLogin() {
        this.isLoading = true;
        this.googleSigninService.signInWithGoogle();
    }
}
