import { Component } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {GoogleSigninService} from '../../services/google-signin.service';

@Component({
  selector: 'app-home',
  standalone: false,

  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {
    constructor(private http: HttpClient, private googleSignInService: GoogleSigninService) {
        const idToken = this.googleSignInService.idToken;
        this.http.post('https://localhost:5001/api/auth/google-response', { idToken : idToken })
            .subscribe(response => {
                console.log('Backend response:', response);
            });
    }
}
