import { Component } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {GoogleSigninService} from '../../services/google-signin.service';
import {environment} from '../../../environments/environment';

@Component({
  selector: 'app-home',
  standalone: false,

  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {

    private googleLoginUrl = `${environment.serverUrl}/api/auth/google-response`;

    constructor(private http: HttpClient, private googleSignInService: GoogleSigninService) {
        const idToken = this.googleSignInService.idToken;
        this.http.post(this.googleLoginUrl, { idToken : idToken })
            .subscribe(response => {
                console.log('Backend response:', response);
            });
    }
}
