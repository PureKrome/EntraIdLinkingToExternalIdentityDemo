# Azure EntraID demo signing in with an linked IdP

## Summary

This application demonstrates how Azure EntraID can be used to sign in with an exteral identity (aka. an external IdP) *where the main user account exists in EntraID*

## Details

A lot of people want the option to signin to a webapp either using their own username/password OR linking an account to an external identity provider like Google, etc.

The trick this demo explores is that the linked external IdP details are stored in EntraID .. not your own database. This means we can use the normal EntraID signin modal/page instead of creating custom signin pages and having to do MORE work to handle authentication, which then means you might just create more security risks/potential attack vectors.

### What does this look like?

When we sign into our app using EntraID, this is what a default page looks like:

<img width="895" height="403" alt="Image" src="https://github.com/user-attachments/assets/ffdc53a4-2490-4cd7-b3ce-78cb5dba4e55" />

<img width="652" height="474" alt="Image" src="https://github.com/user-attachments/assets/995fc037-7f25-4f29-89ef-f406d6aa60ab" />

- Create an account in EntraID (e.g. via the Azure Portal)
- Now sign in via your EntraID credentials (username and password)
- Now that you are authenticated, we can link this authenticated account to your External Identity. In this demo, it's your custom Google Account

- Now link your account.  

<img width="1648" height="712" alt="Image" src="https://github.com/user-attachments/assets/a84c6f60-cb59-447b-a97e-f087e9a07d48" />

- Sign out
- Sign in but choose a different account (so it doesn't try to autnenticate against your EntraID). ** This option might now show, depending on how you 'remembered' your previous autentication
- Now select Google as the method of authenticating / proving your credentials.
- Sign in to Google with the previously used/linked Google credentials.
- Now you should be authenticated against your EntraID account using your Google authentication details.


## How to setup this demo so you can test/play
- Create an EntraID tenant + App Registration + workflow, etc. (out of scope because it's a real PITA)
- Grab the following details and paste them into the configuration "Secrets" or `appsettings.json` etc.
  - `Authority`. Its in the format: `"https://<EntraID Name>.ciamlogin.com/<TenantId GUID>/v2.0"`. e.g. `https://fancypants.ciamlogin.com/11111111-2222-3333-4444-555555555555/v2.0`
  - `ClientId`. (From the App Registrations -> Select App -> Overview)  

    <img width="836" height="436" alt="Image" src="https://github.com/user-attachments/assets/7d917c6a-7532-4a57-bfec-a3ff346078e1" />
  - `ClientSecret` (From the App Registrations -> Select App -> Credentials and Secrets)  
    
    <img width="1303" height="577" alt="Image" src="https://github.com/user-attachments/assets/3b5bec0e-e914-4f0c-9476-a9532e03b59f" />
  - `TenantId` and `Domain` (From the main EntraID Overview)  
    <img width="805" height="507" alt="Image" src="https://github.com/user-attachments/assets/943d8b52-a373-485d-8060-2bad546b7b3b" />
  - Google `ClientId` and `ClientSecret` (From Auth Platform)
    - The following Authorised Redirect Url's are required:
      - `https://login.microsoftonline.com`
      - `https://login.microsoftonline.com/te/[EntraID TenantId]/oauth2/authresp`
      - `https://login.microsoftonline.com/te/[EntraID Domain]/oauth2/authresp` (.e.g. `https://login.microsoftonline.com/te/fancypants.onmicrosoft.com/oauth2/authresp`)
      - `https://[EntraID TenantId].ciamlogin.com/[EntraID TenantId]/federation/oidc/accounts.google.com`
      - `https://[EntraID TenantId].ciamlogin.com/[EntraID Domain]/federation/oidc/accounts.google.com`
      - `https://[EntraID Project name].ciamlogin.com/[EntraID TenantId]/federation/oauth2` (e.g. `https://fancypants.ciamlogin.com/11111111-2222-3333-4444-555555555555/federation/oauth2)`
      - `https://[EntraID Project name].ciamlogin.com/EntraID Project Name].onmicrosoft.com/federation/oauth2` (e.g. `https://fancypants.ciamlogin.com/fancypants.onmicrosoft.com/federation/oauth2`)
      - `https://localhost:7175/signin-google`


---

## Contribute
Yep - contributions are always welcome. Please read the contribution guidelines first.

## Code of Conduct

If you wish to participate in this repository then you need to abide by the code of conduct.

## Feedback

Yes! Please use the Issues section to provide feedback - either good or needs improvement :cool:
