import { Component } from '@angular/core';

@Component({
  selector: 'app-login',
  standalone: false,

  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent {
    username: string = '';
    password: string = '';

    onLoginSubmit() {
        console.log('Login submitted');
        // Handle the login logic here
    }

    onRegisterSubmit() {
        console.log('Register submitted');
        // Handle the registration logic here
    }
}
