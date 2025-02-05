import {Component, OnInit} from '@angular/core';
import {AuthService} from '../../services/auth.service';
import {GoogleSigninService} from '../../services/google-signin.service';

declare const google: any;

@Component({
    selector: 'app-login',
    standalone: false,

    templateUrl: './login.component.html',
    styleUrl: './login.component.scss'
})
export class LoginComponent implements OnInit {
    username: string = '';
    password: string = '';

    constructor(private authService: AuthService, private googleSigninService: GoogleSigninService) {
    }

    ngOnInit(): void {
    }

    onLoginSubmit() {
        this.authService.signin(this.username, this.password)
            .subscribe(x => console.log(x));
        console.log('Login submitted');
        // Handle the login logic here
    }

    onRegisterSubmit() {
        console.log('Register submitted');
        // Handle the registration logic here
    }

    googleLogin() {
        this.googleSigninService.signInWithGoogle();
    }
}
